use std::{
    cell::Cell,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock, RwLock,
    },
    time::SystemTime,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::Encode;
use kmr_common::{
    crypto::{ec, rsa, KeyMaterial, Sha256},
    Error,
};
use kmr_crypto_boring::{ec::BoringEc, mldsa::BoringMlDsa, rsa::BoringRsa, sha256::BoringSha256};
use kmr_ta::device::{
    RetrieveCertSigningInfo, SigningAlgorithm, SigningInfoSnapshot, SigningKeyType,
};
use kmr_wire::keymint;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use x509_cert::der as x509_der;
use x509_cert::Certificate;

pub const KEYBOX_PATH: &str = "/data/misc/keystore/omk/keybox.xml";

const BUNDLED_KEYBOX_XML: &str = include_str!("../template/keybox.xml");

lazy_static::lazy_static! {
    pub static ref KEYBOX: RwLock<KeyBox> = RwLock::new(KeyBox::new());
    static ref KEYBOX_IO_LOCK: Mutex<()> = Mutex::new(());
}

static KEYBOX_WATCHER: OnceLock<()> = OnceLock::new();
static KEYBOX_DB_RETIRE_ALLOWED: AtomicBool = AtomicBool::new(false);
static KEYBOX_RUNTIME_LOADED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct CertSignAlgoInfo {
    key: KeyMaterial,
    key_der: Vec<u8>,
    chain: Vec<keymint::Certificate>,
}

/// One `<Keybox>` block: an EC signing entry and, optionally, its RSA counterpart.
/// The EC leaf certificate serial identifies the keybox for per-UID assignment.
#[derive(Clone)]
pub struct KeyboxEntry {
    rsa_info: Option<CertSignAlgoInfo>,
    ec_info: CertSignAlgoInfo,
    identity_digest: [u8; 32],
    serial: Vec<u8>,
    not_after: SystemTime,
}

#[derive(Clone)]
pub struct KeyBox {
    keyboxes: Vec<KeyboxEntry>,
    /// The bundled template is a fallback, not a provisioned keybox, so it may sign with
    /// expired entries instead of failing attestation.
    bundled_fallback: bool,
}

#[derive(Clone, Copy)]
enum KeyAlgorithm {
    Ec,
    Rsa,
}

struct ParsedKeyEntry {
    key_der: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename = "AndroidAttestation")]
struct KeyboxXml {
    #[serde(rename = "NumberOfKeyboxes", default)]
    number_of_keyboxes: usize,
    #[serde(rename = "Keybox", default)]
    keyboxes: Vec<KeyboxBlockXml>,
}

#[derive(Clone, Deserialize, Serialize)]
struct KeyboxBlockXml {
    #[serde(rename = "@DeviceID", default)]
    device_id: String,
    #[serde(rename = "Key", default)]
    keys: Vec<KeyXml>,
}

#[derive(Clone, Deserialize, Serialize)]
struct KeyXml {
    #[serde(rename = "@algorithm")]
    algorithm: String,
    #[serde(rename = "PrivateKey")]
    private_key: PemBlockXml,
    #[serde(rename = "CertificateChain")]
    certificate_chain: CertificateChainXml,
}

#[derive(Clone, Deserialize, Serialize)]
struct CertificateChainXml {
    #[serde(rename = "NumberOfCertificates")]
    number_of_certificates: usize,
    #[serde(rename = "Certificate", default)]
    certificates: Vec<PemBlockXml>,
}

#[derive(Clone, Deserialize, Serialize)]
struct PemBlockXml {
    #[serde(rename = "@format", default)]
    format: String,
    #[serde(rename = "$text")]
    body: String,
}

thread_local! {
    static ATTESTATION_UID: Cell<Option<u32>> = const { Cell::new(None) };
    static ATTESTATION_DIGEST: Cell<Option<[u8; 32]>> = const { Cell::new(None) };
}

/// Marks the calling UID for the duration of one key-creation request so that the TA's
/// `RetrieveCertSigningInfo` implementation can pick the UID's keybox.
pub struct AttestationRequestScope;

pub fn attestation_request_scope(uid: u32) -> AttestationRequestScope {
    ATTESTATION_UID.with(|cell| cell.set(Some(uid)));
    ATTESTATION_DIGEST.with(|cell| cell.set(None));
    AttestationRequestScope
}

impl Drop for AttestationRequestScope {
    fn drop(&mut self) {
        ATTESTATION_UID.with(|cell| cell.set(None));
        ATTESTATION_DIGEST.with(|cell| cell.set(None));
    }
}

impl KeyBox {
    pub fn new() -> Self {
        let mut keybox =
            Self::from_xml_str(BUNDLED_KEYBOX_XML).expect("bundled keybox.xml must be valid");
        keybox.bundled_fallback = true;
        keybox
    }

    pub fn from_xml_str(xml: &str) -> Result<Self> {
        let document: KeyboxXml =
            quick_xml::de::from_str(xml).context("failed to parse keybox.xml")?;
        if document.keyboxes.is_empty() {
            bail!("keybox.xml has no <Keybox> blocks");
        }

        let mut keyboxes = Vec::with_capacity(document.keyboxes.len());
        for block in document.keyboxes {
            keyboxes.push(KeyboxEntry::from_xml(block)?);
        }

        let keybox = Self {
            keyboxes,
            bundled_fallback: false,
        };
        keybox.validate_serial_uniqueness()?;
        Ok(keybox)
    }

    fn validate_serial_uniqueness(&self) -> Result<()> {
        for (index, keybox) in self.keyboxes.iter().enumerate() {
            if self.keyboxes[..index]
                .iter()
                .any(|other| other.serial == keybox.serial)
            {
                bail!(
                    "duplicate keybox serial number {} in keybox.xml",
                    hex::encode(&keybox.serial)
                );
            }
        }
        Ok(())
    }

    fn build_rsa_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("RSA certificate chain is empty");
        }
        let key = rsa::import_pkcs1_key(&entry.key_der)
            .map(|(key, _, _)| key)
            .map_err(|e| anyhow!("failed to import RSA private key: {e:?}"))?;
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Rsa)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der: entry.key_der,
            chain,
        })
    }

    fn build_ec_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("EC certificate chain is empty");
        }
        let key = ec::import_sec1_private_key(&entry.key_der)
            .map_err(|e| anyhow!("failed to import EC private key: {e:?}"))?;
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Ec)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der: entry.key_der,
            chain,
        })
    }

    fn compute_identity_digest(
        rsa_info: Option<&CertSignAlgoInfo>,
        ec_info: &CertSignAlgoInfo,
    ) -> Result<[u8; 32]> {
        let mut material = Vec::new();
        if let Some(rsa_info) = rsa_info {
            append_labeled_bytes(&mut material, b"rsa-key", &rsa_info.key_der);
            append_labeled_chain(&mut material, b"rsa-chain", &rsa_info.chain);
        }
        append_labeled_bytes(&mut material, b"ec-key", &ec_info.key_der);
        append_labeled_chain(&mut material, b"ec-chain", &ec_info.chain);

        BoringSha256 {}
            .hash(&material)
            .map_err(|e| anyhow!("failed to hash keybox identity: {e:?}"))
    }

    /// Digests of every entry, for stale-key retirement.
    pub fn active_identity_digests(&self) -> Vec<[u8; 32]> {
        self.keyboxes
            .iter()
            .map(|keybox| keybox.identity_digest)
            .collect()
    }

    /// Default keybox digest, used when no caller-scoped selection applies.
    pub fn identity_digest(&self) -> [u8; 32] {
        self.keyboxes
            .first()
            .map(|keybox| keybox.identity_digest)
            .unwrap_or_default()
    }

    fn usable_serials(&self) -> Vec<Vec<u8>> {
        self.keyboxes
            .iter()
            .filter(|keybox| self.bundled_fallback || !keybox.is_expired())
            .map(|keybox| keybox.serial.clone())
            .collect()
    }

    fn select_for_uid(&self, uid: u32) -> Result<&KeyboxEntry, Error> {
        let valid = self.usable_serials();
        if valid.is_empty() {
            return Err(kmr_common::km_err!(
                AttestationKeysNotProvisioned,
                "all keybox entries have expired"
            ));
        }

        let serial = match crate::global::DB
            .with(|db| db.borrow_mut().resolve_keybox_serial(uid as i64, &valid))
        {
            Ok(serial) => serial,
            Err(error) => {
                error!("failed to resolve keybox binding for uid {uid}: {error:#}");
                return Err(kmr_common::km_err!(
                    UnknownError,
                    "failed to resolve keybox binding"
                ));
            }
        };

        self.keyboxes
            .iter()
            .find(|keybox| keybox.serial == serial)
            .ok_or_else(|| kmr_common::km_err!(UnknownError, "selected keybox serial not found"))
    }
}

impl KeyboxEntry {
    fn from_xml(block: KeyboxBlockXml) -> Result<Self> {
        let mut rsa_info = None;
        let mut ec_info = None;

        for key in block.keys {
            let algorithm = match key.algorithm.trim() {
                "ecdsa" | "ec" => KeyAlgorithm::Ec,
                "rsa" => KeyAlgorithm::Rsa,
                other => bail!("unsupported key algorithm `{other}` in keybox.xml"),
            };
            let entry = ParsedKeyEntry::from_xml(key).with_context(|| {
                format!("failed to parse {:?} key entry", algorithm_name(algorithm))
            })?;
            let info = match algorithm {
                KeyAlgorithm::Ec => KeyBox::build_ec_info(entry)?,
                KeyAlgorithm::Rsa => KeyBox::build_rsa_info(entry)?,
            };
            match algorithm {
                KeyAlgorithm::Ec => ec_info = Some(info),
                KeyAlgorithm::Rsa => rsa_info = Some(info),
            }
        }

        let ec_info = ec_info.context("missing EC key entry in keybox.xml")?;
        Self::new(ec_info, rsa_info)
    }

    fn new(ec_info: CertSignAlgoInfo, rsa_info: Option<CertSignAlgoInfo>) -> Result<Self> {
        let identity_digest = KeyBox::compute_identity_digest(rsa_info.as_ref(), &ec_info)?;
        let (serial, not_after) = Self::serial_and_expiry(
            &ec_info.chain,
            rsa_info.as_ref().map(|info| info.chain.as_slice()),
        )?;
        Ok(Self {
            rsa_info,
            ec_info,
            identity_digest,
            serial,
            not_after,
        })
    }

    /// EC leaf serial, and the earliest `notAfter` across both chains.
    fn serial_and_expiry(
        ec_chain: &[keymint::Certificate],
        rsa_chain: Option<&[keymint::Certificate]>,
    ) -> Result<(Vec<u8>, SystemTime)> {
        let ec_leaf = ec_chain.first().context("EC certificate chain is empty")?;
        let ec_leaf = <Certificate as x509_der::Decode>::from_der(&ec_leaf.encoded_certificate)
            .context("failed to parse EC leaf certificate")?;
        let serial = ec_leaf
            .tbs_certificate()
            .serial_number()
            .as_bytes()
            .to_vec();
        let mut not_after = ec_leaf
            .tbs_certificate()
            .validity()
            .not_after
            .to_system_time();

        for certificate in ec_chain.iter().skip(1).chain(rsa_chain.unwrap_or_default()) {
            let parsed =
                <Certificate as x509_der::Decode>::from_der(&certificate.encoded_certificate)
                    .context("failed to parse keybox certificate")?;
            let expiry = parsed
                .tbs_certificate()
                .validity()
                .not_after
                .to_system_time();
            not_after = not_after.min(expiry);
        }

        Ok((serial, not_after))
    }

    fn is_expired(&self) -> bool {
        self.not_after <= SystemTime::now()
    }

    #[cfg(test)]
    fn to_xml(&self) -> KeyboxBlockXml {
        let mut keys = vec![KeyBox::to_xml_block(&self.ec_info, KeyAlgorithm::Ec)];
        if let Some(rsa_info) = &self.rsa_info {
            keys.push(KeyBox::to_xml_block(rsa_info, KeyAlgorithm::Rsa));
        }
        KeyboxBlockXml {
            device_id: "sw".to_string(),
            keys,
        }
    }

    fn signing_entry(&self, algorithm: SigningAlgorithm) -> &CertSignAlgoInfo {
        match (algorithm, self.rsa_info.as_ref()) {
            // An EC-only keybox signs RSA-hinted attestations with the EC key and chain.
            (SigningAlgorithm::Rsa, Some(rsa_info)) => rsa_info,
            _ => &self.ec_info,
        }
    }

    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        let info = self.signing_entry(key_type.algo_hint);

        Ok(SigningInfoSnapshot {
            signing_key: info.key.clone(),
            cert_chain: info.chain.clone(),
            identity_digest: self.identity_digest,
        })
    }
}

#[cfg(test)]
impl KeyBox {
    pub fn to_xml_string(&self) -> String {
        let document = KeyboxXml {
            number_of_keyboxes: self.keyboxes.len(),
            keyboxes: self.keyboxes.iter().map(KeyboxEntry::to_xml).collect(),
        };
        let body = quick_xml::se::to_string(&document).expect("keybox XML serialization failed");
        format!("<?xml version=\"1.0\"?>\n{body}\n")
    }

    fn to_xml_block(info: &CertSignAlgoInfo, algorithm: KeyAlgorithm) -> KeyXml {
        let (name, private_label) = match algorithm {
            KeyAlgorithm::Ec => ("ecdsa", "EC PRIVATE KEY"),
            KeyAlgorithm::Rsa => ("rsa", "RSA PRIVATE KEY"),
        };
        KeyXml {
            algorithm: name.to_string(),
            private_key: PemBlockXml {
                format: "pem".to_string(),
                body: encode_pem_block(private_label, &info.key_der),
            },
            certificate_chain: CertificateChainXml {
                number_of_certificates: info.chain.len(),
                certificates: info
                    .chain
                    .iter()
                    .map(|certificate| PemBlockXml {
                        format: "pem".to_string(),
                        body: encode_pem_block("CERTIFICATE", &certificate.encoded_certificate),
                    })
                    .collect(),
            },
        }
    }
}

impl Default for KeyBox {
    fn default() -> Self {
        Self::new()
    }
}

impl ParsedKeyEntry {
    fn from_xml(key: KeyXml) -> Result<Self> {
        let key_der = decode_pem(&key.private_key.body)?;
        let chain = key
            .certificate_chain
            .certificates
            .iter()
            .map(|certificate| decode_pem(&certificate.body))
            .collect::<Result<Vec<_>>>()?;

        let expected_cert_count = key.certificate_chain.number_of_certificates;
        if chain.len() != expected_cert_count {
            bail!(
                "certificate count mismatch: declared {}, parsed {}",
                expected_cert_count,
                chain.len()
            );
        }

        Ok(Self { key_der, chain })
    }
}

fn append_labeled_bytes(buffer: &mut Vec<u8>, label: &[u8], data: &[u8]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(data);
}

fn append_labeled_chain(buffer: &mut Vec<u8>, label: &[u8], chain: &[keymint::Certificate]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(chain.len() as u32).to_be_bytes());
    for certificate in chain {
        buffer.extend_from_slice(&(certificate.encoded_certificate.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&certificate.encoded_certificate);
    }
}

fn algorithm_name(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ec => "EC",
        KeyAlgorithm::Rsa => "RSA",
    }
}

fn validate_chain_matches_key(
    key: &KeyMaterial,
    chain: &[keymint::Certificate],
    algorithm: KeyAlgorithm,
) -> Result<()> {
    let first_cert = chain
        .first()
        .context("certificate chain must contain a leaf certificate")?;
    let certificate = <Certificate as x509_der::Decode>::from_der(&first_cert.encoded_certificate)
        .with_context(|| {
            format!(
                "failed to parse {} leaf certificate from keybox chain",
                algorithm_name(algorithm)
            )
        })?;
    let mut spki_buf = Vec::new();
    let derived_spki = key
        .subject_public_key_info(
            &mut spki_buf,
            &BoringEc::default(),
            &BoringRsa::default(),
            &BoringMlDsa,
        )
        .map_err(|e| {
            anyhow!(
                "failed to derive {} public key info from private key: {e:?}",
                algorithm_name(algorithm)
            )
        })?
        .context("symmetric key cannot back an attestation certificate")?
        .to_der()
        .with_context(|| {
            format!(
                "failed to encode {} public key info from private key",
                algorithm_name(algorithm)
            )
        })?;
    let certificate_spki =
        x509_der::Encode::to_der(certificate.tbs_certificate().subject_public_key_info())
            .with_context(|| {
                format!(
                    "failed to encode {} public key info from certificate chain",
                    algorithm_name(algorithm)
                )
            })?;
    if derived_spki != certificate_spki {
        bail!(
            "{} certificate chain does not match the supplied private key",
            algorithm_name(algorithm)
        );
    }
    Ok(())
}

fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let base64_body = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect::<String>();

    if base64_body.is_empty() {
        bail!("empty PEM payload");
    }

    STANDARD
        .decode(base64_body.as_bytes())
        .context("failed to decode PEM payload")
}

#[cfg(test)]
fn encode_pem_block(label: &str, der: &[u8]) -> String {
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {label}-----\n"));
    let base64 = STANDARD.encode(der);
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid UTF-8"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----"));
    pem
}

fn temp_keybox_path(path: &str) -> PathBuf {
    let target = Path::new(path);
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("keybox.xml");
    let temp_name = format!(".{file_name}.tmp-{}", std::process::id());
    target
        .parent()
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}

fn write_keybox_xml(path: &str, xml: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create keybox directory {}", parent.display()))?;
    }
    let temp_path = temp_keybox_path(path);
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .with_context(|| {
                format!(
                    "failed to open temporary keybox.xml {}",
                    temp_path.display()
                )
            })?;
        file.write_all(xml.as_bytes()).with_context(|| {
            format!(
                "failed to write temporary keybox.xml {}",
                temp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "failed to sync temporary keybox.xml {}",
                temp_path.display()
            )
        })?;
    }

    #[cfg(windows)]
    if Path::new(path).exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to replace keybox.xml at {path} on Windows"))?;
    }

    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to atomically replace keybox.xml at {path}"))
}

fn write_bundled_keybox(path: &str) -> Result<()> {
    write_keybox_xml(path, BUNDLED_KEYBOX_XML)
}

pub fn ensure_keybox_file(path: &str) -> Result<()> {
    if Path::new(path).exists() {
        return Ok(());
    }
    info!("keybox.xml missing at {}; seeding bundled template", path);
    write_bundled_keybox(path)
}

fn is_bundled_keybox_xml(xml: &str) -> bool {
    xml.trim() == BUNDLED_KEYBOX_XML.trim()
}

fn retire_stale_keybox_bound_entries(active_identities: &[[u8; 32]]) {
    if !db_retirement_allowed() {
        debug!("skipping stale keybox-bound DB retirement (disabled or fallback keybox active)");
        return;
    }

    match crate::global::DB.with(|db| {
        db.borrow_mut()
            .retire_stale_keybox_bound_entries(active_identities)
    }) {
        Ok(0) => debug!("no stale keybox-bound key entries needed retirement"),
        Ok(retired) => info!("retired {retired} stale keybox-bound key entries"),
        Err(error) => error!("failed to retire stale keybox-bound key entries: {error:#}"),
    }
}

fn install_keybox(
    new_keybox: KeyBox,
    retire_db_entries: bool,
    db_retirement_allowed: bool,
) -> bool {
    let new_identities = new_keybox.active_identity_digests();
    let changed = {
        let mut keybox = KEYBOX.write().unwrap();
        let changed = keybox.active_identity_digests() != new_identities;
        *keybox = new_keybox;
        changed
    };
    KEYBOX_DB_RETIRE_ALLOWED.store(db_retirement_allowed, Ordering::Release);
    KEYBOX_RUNTIME_LOADED.store(true, Ordering::Release);

    if changed {
        crate::keymaster::keymint_device::clear_initialized_attestation_caches();
    }

    if retire_db_entries {
        retire_stale_keybox_bound_entries(&new_identities);
    }

    changed
}

pub fn db_retirement_allowed() -> bool {
    KEYBOX_DB_RETIRE_ALLOWED.load(Ordering::Acquire)
        && match crate::config::config().read() {
            Ok(config) => config.main.retire_stale_keybox_bound_keys,
            Err(_) => {
                error!("config lock poisoned while checking keybox retirement");
                false
            }
        }
}

fn is_fallback_continuation(keybox: &KeyBox, contents: &str) -> bool {
    let current_identity = KEYBOX
        .read()
        .map(|current| current.identity_digest())
        .unwrap_or([0u8; 32]);
    is_fallback_continuation_with_state(
        keybox,
        contents,
        KEYBOX_RUNTIME_LOADED.load(Ordering::Acquire),
        KEYBOX_DB_RETIRE_ALLOWED.load(Ordering::Acquire),
        current_identity,
    )
}

fn is_fallback_continuation_with_state(
    keybox: &KeyBox,
    contents: &str,
    runtime_loaded: bool,
    retirement_allowed: bool,
    current_identity: [u8; 32],
) -> bool {
    runtime_loaded
        && !retirement_allowed
        && is_bundled_keybox_xml(contents)
        && current_identity == keybox.identity_digest()
}

fn load_keybox_with_fallback(path: &str) -> Result<(KeyBox, bool)> {
    match fs::read_to_string(path) {
        Ok(contents) => match KeyBox::from_xml_str(&contents) {
            Ok(mut keybox) => {
                let fallback_origin = is_fallback_continuation(&keybox, &contents);
                keybox.bundled_fallback = is_bundled_keybox_xml(&contents);
                Ok((keybox, fallback_origin))
            }
            Err(error) => {
                warn!(
                    "invalid keybox.xml at {}: {:#}; rewriting bundled template",
                    path, error
                );
                write_bundled_keybox(path)?;
                Ok((KeyBox::new(), true))
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!("keybox.xml missing at {}; writing bundled template", path);
            write_bundled_keybox(path)?;
            Ok((KeyBox::new(), true))
        }
        Err(error) => Err(error).with_context(|| format!("failed to read keybox.xml from {path}")),
    }
}

pub fn reload_from_disk() -> Result<bool> {
    reload_from_disk_inner(true)
}

fn reload_from_disk_inner(retire_db_entries: bool) -> Result<bool> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, used_fallback) = load_keybox_with_fallback(KEYBOX_PATH)?;
    let changed = install_keybox(keybox, retire_db_entries, !used_fallback);
    if changed {
        info!(
            "active keybox identity updated from {} (fallback={})",
            KEYBOX_PATH, used_fallback
        );
    } else {
        debug!(
            "keybox reload completed without identity change (fallback={})",
            used_fallback
        );
    }
    Ok(changed)
}

pub fn initialize() -> Result<()> {
    ensure_keybox_file(KEYBOX_PATH)?;
    reload_from_disk_inner(false)?;
    KEYBOX_WATCHER.get_or_init(|| {
        if let Err(error) = kmr_common::runtime::file_watch::spawn_path_watcher(
            "omk-keybox-watch",
            PathBuf::from(KEYBOX_PATH),
            |_trigger| {
                if let Err(reload_error) = reload_from_disk() {
                    error!("failed to reload keybox.xml after change: {reload_error:#}");
                }
            },
        ) {
            error!("failed to watch keybox.xml: {error:#}");
        }
    });
    Ok(())
}

pub fn active_identity_digests() -> Vec<[u8; 32]> {
    KEYBOX.read().unwrap().active_identity_digests()
}

/// Digest bound to a key created by the current request, or the default keybox digest.
pub fn current_identity_digest() -> [u8; 32] {
    ATTESTATION_DIGEST
        .with(Cell::get)
        .unwrap_or_else(|| KEYBOX.read().unwrap().identity_digest())
}

pub(crate) fn signing_certificate_ders_from_disk() -> Result<Vec<Vec<u8>>> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, _) = load_keybox_with_fallback(KEYBOX_PATH)?;
    let mut ders = Vec::with_capacity(keybox.keyboxes.len() * 2);
    for entry in &keybox.keyboxes {
        if let Some(rsa_info) = &entry.rsa_info {
            ders.push(rsa_info.chain[0].encoded_certificate.clone());
        }
        ders.push(entry.ec_info.chain[0].encoded_certificate.clone());
    }
    Ok(ders)
}

pub struct KeyboxManager;

impl RetrieveCertSigningInfo for KeyboxManager {
    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        let keybox = KEYBOX
            .read()
            .map_err(|_| kmr_common::km_err!(UnknownError, "failed to lock KEYBOX"))?;
        let uid = ATTESTATION_UID.with(Cell::get).ok_or_else(|| {
            kmr_common::km_err!(UnknownError, "attestation request has no caller UID scope")
        })?;
        let selected = keybox.select_for_uid(uid)?;
        ATTESTATION_DIGEST.with(|cell| cell.set(Some(selected.identity_digest)));
        selected.signing_info(key_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_ta::device::SigningKey;

    fn write_temp_keybox(name: &str, contents: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("omk-keybox-{name}-{}.xml", std::process::id()));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_bundled_template() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        assert_eq!(keybox.keyboxes.len(), 1);
        assert_eq!(keybox.keyboxes[0].ec_info.chain.len(), 2);
        assert_eq!(keybox.keyboxes[0].rsa_info.as_ref().unwrap().chain.len(), 2);
        assert_ne!(keybox.identity_digest(), [0u8; 32]);
        assert!(!keybox.keyboxes[0].serial.is_empty());
    }

    #[test]
    fn expired_entries_fail_unless_bundled_fallback() {
        let mut provisioned = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let mut fallback = KeyBox::new();
        for keybox in [&mut provisioned, &mut fallback] {
            for entry in &mut keybox.keyboxes {
                entry.not_after = SystemTime::UNIX_EPOCH;
            }
        }

        let error = match provisioned.select_for_uid(1000) {
            Err(error) => error,
            Ok(_) => panic!("expected expired keybox rejection"),
        };
        assert!(matches!(
            error.kind(),
            kmr_common::ErrorKind::Hal(keymint::ErrorCode::AttestationKeysNotProvisioned, _)
        ));

        assert_eq!(fallback.usable_serials().len(), fallback.keyboxes.len());
    }

    #[test]
    fn rejects_invalid_xml() {
        assert!(KeyBox::from_xml_str("<AndroidAttestation/>").is_err());
    }

    #[test]
    fn rejects_duplicate_keybox_serials() {
        let mut document: KeyboxXml = quick_xml::de::from_str(BUNDLED_KEYBOX_XML).unwrap();
        let duplicated = document.keyboxes[0].clone();
        document.keyboxes.push(duplicated);
        assert!(KeyBox::from_xml_str(&quick_xml::se::to_string(&document).unwrap()).is_err());
    }

    #[test]
    fn parses_local_multi_keybox_file() {
        // Local-only material (build/ is gitignored); skipped when absent.
        let Ok(xml) = fs::read_to_string("build/keybox.xml") else {
            return;
        };
        let keybox = KeyBox::from_xml_str(&xml).unwrap();
        assert!(keybox.keyboxes.len() > 1);
        let mut serials = std::collections::BTreeSet::new();
        assert!(keybox
            .keyboxes
            .iter()
            .all(|entry| serials.insert(entry.serial.clone())));
    }

    #[test]
    fn request_scope_exposes_resolved_digest() {
        let default = KeyBox::new().identity_digest();
        assert_eq!(current_identity_digest(), default);
        {
            let _scope = attestation_request_scope(1234);
            assert_eq!(current_identity_digest(), default);
            ATTESTATION_DIGEST.with(|cell| cell.set(Some([7u8; 32])));
            assert_eq!(current_identity_digest(), [7u8; 32]);
        }
        assert_eq!(current_identity_digest(), default);
    }

    #[test]
    fn unscoped_attestation_is_rejected() {
        let error = match KeyboxManager.signing_info(SigningKeyType {
            which: SigningKey::Batch,
            algo_hint: SigningAlgorithm::Ec,
        }) {
            Err(error) => error,
            Ok(_) => panic!("expected unscoped attestation to be rejected"),
        };
        assert!(matches!(
            error.kind(),
            kmr_common::ErrorKind::Hal(keymint::ErrorCode::UnknownError, _)
        ));
    }

    #[test]
    fn identity_changes_when_chain_changes() {
        let original = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let mut entry = original.keyboxes[0].clone();
        let leaf = entry.ec_info.chain[0].clone();
        entry.ec_info.chain.push(leaf);

        let mut changed = original.clone();
        changed.keyboxes[0] = KeyboxEntry::new(entry.ec_info, entry.rsa_info).unwrap();
        let modified = KeyBox::from_xml_str(&changed.to_xml_string()).unwrap();
        assert_ne!(original.identity_digest(), modified.identity_digest());
    }

    #[test]
    fn rejects_mismatched_private_key_and_certificate_chain() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let rsa_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.keyboxes[0].rsa_info.as_ref().unwrap().chain[0].encoded_certificate,
        );
        let ec_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.keyboxes[0].ec_info.chain[0].encoded_certificate,
        );
        let modified_xml = BUNDLED_KEYBOX_XML.replacen(&rsa_cert, &ec_cert, 1);
        assert!(KeyBox::from_xml_str(&modified_xml).is_err());
    }

    #[test]
    fn signing_snapshot_keeps_key_chain_and_digest_in_sync() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let entry = &keybox.keyboxes[0];

        let rsa_snapshot = entry
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Rsa,
            })
            .unwrap();
        assert_eq!(rsa_snapshot.identity_digest, keybox.identity_digest());
        validate_chain_matches_key(
            &rsa_snapshot.signing_key,
            &rsa_snapshot.cert_chain,
            KeyAlgorithm::Rsa,
        )
        .unwrap();

        let ec_snapshot = entry
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Ec,
            })
            .unwrap();
        assert_eq!(ec_snapshot.identity_digest, keybox.identity_digest());
        validate_chain_matches_key(
            &ec_snapshot.signing_key,
            &ec_snapshot.cert_chain,
            KeyAlgorithm::Ec,
        )
        .unwrap();
    }

    #[test]
    fn ec_only_keybox_signs_rsa_attestation_with_ec_key() {
        let mut document: KeyboxXml = quick_xml::de::from_str(BUNDLED_KEYBOX_XML).unwrap();
        for block in &mut document.keyboxes {
            block.keys.retain(|key| key.algorithm != "rsa");
        }
        let ec_only_xml = quick_xml::se::to_string(&document).unwrap();
        let keybox = KeyBox::from_xml_str(&ec_only_xml).unwrap();
        let entry = &keybox.keyboxes[0];

        let ec_snapshot = entry
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Ec,
            })
            .unwrap();
        let rsa_snapshot = entry
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Rsa,
            })
            .unwrap();

        assert_eq!(rsa_snapshot.signing_key, ec_snapshot.signing_key);
        assert_eq!(rsa_snapshot.cert_chain, ec_snapshot.cert_chain);
        assert_eq!(rsa_snapshot.identity_digest, ec_snapshot.identity_digest);
        assert!(entry.rsa_info.is_none());
        validate_chain_matches_key(
            &rsa_snapshot.signing_key,
            &rsa_snapshot.cert_chain,
            KeyAlgorithm::Ec,
        )
        .unwrap();

        // Switching from the bundled RSA entry to the EC entry must invalidate cached
        // attestation chains.
        let bundled_rsa_snapshot = KeyBox::new().keyboxes[0]
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Rsa,
            })
            .unwrap();
        assert_ne!(
            bundled_rsa_snapshot.identity_digest,
            rsa_snapshot.identity_digest
        );
        // Dropping the RSA entry changes the keybox identity; keys bound to the previous
        // identity are not carried over.
        assert_ne!(keybox.identity_digest(), KeyBox::new().identity_digest());

        let rewritten = keybox.to_xml_string();
        assert!(!rewritten.contains("algorithm=\"rsa\""));
        assert!(rewritten.contains("<Keybox DeviceID=\"sw\">"));
        assert!(rewritten.contains("<NumberOfKeyboxes>1</NumberOfKeyboxes>"));
        assert!(KeyBox::from_xml_str(&rewritten).is_ok());
    }

    #[test]
    fn invalid_file_falls_back_to_bundled_template() {
        let path = write_temp_keybox("invalid", "<not-xml>");
        let (keybox, used_fallback) = load_keybox_with_fallback(path.to_str().unwrap()).unwrap();
        assert!(used_fallback);
        assert_eq!(keybox.identity_digest(), KeyBox::new().identity_digest());
        let written = fs::read_to_string(path).unwrap();
        assert!(written.contains("<AndroidAttestation>"));
    }

    #[test]
    fn explicit_bundled_template_is_retirement_eligible_before_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            false,
            false,
            keybox.identity_digest(),
        ));
    }

    #[test]
    fn non_bundled_keybox_is_retirement_eligible() {
        let modified_xml = format!("{BUNDLED_KEYBOX_XML}\n<!-- explicit local keybox -->\n");
        let path = write_temp_keybox("modified", &modified_xml);

        let (_, used_fallback) = load_keybox_with_fallback(path.to_str().unwrap()).unwrap();

        assert!(!used_fallback);
    }

    #[test]
    fn rewritten_bundled_template_can_continue_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            false,
            keybox.identity_digest(),
        ));
        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            true,
            keybox.identity_digest(),
        ));
    }
}
