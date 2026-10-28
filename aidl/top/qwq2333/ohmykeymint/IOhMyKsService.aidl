package top.qwq2333.ohmykeymint;

import android.hardware.security.keymint.SecurityLevel;
import android.hardware.security.keymint.Tag;
import android.system.keystore2.Domain;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;

import top.qwq2333.ohmykeymint.IOhMySecurityLevel;
import top.qwq2333.ohmykeymint.CallerInfo;

interface IOhMyKsService {

    IKeystoreSecurityLevel getSecurityLevel(in SecurityLevel securityLevel) = 0;

    IOhMySecurityLevel getOhMySecurityLevel(in SecurityLevel securityLevel) = 1;

    KeyEntryResponse getKeyEntry(in @nullable CallerInfo ctx, in KeyDescriptor key) = 2;


    void updateSubcomponent(in @nullable CallerInfo ctx, in KeyDescriptor key,
                            in @nullable byte[] publicCert, in @nullable byte[] certificateChain) = 3;


    KeyDescriptor[] listEntries(in @nullable CallerInfo ctx, in Domain domain, in long nspace) = 4;


    void deleteKey(in @nullable CallerInfo ctx, in KeyDescriptor key) = 5;


    KeyDescriptor grant(in @nullable CallerInfo ctx, in KeyDescriptor key, in int granteeUid, in int accessVector) = 6;


    void ungrant(in @nullable CallerInfo ctx, in KeyDescriptor key, in int granteeUid) = 7;


    int getNumberOfEntries(in @nullable CallerInfo ctx, in Domain domain, in long nspace) = 8;


    KeyDescriptor[] listEntriesBatched(in @nullable CallerInfo ctx, in Domain domain, in long nspace,
            in @nullable String startingPastAlias) = 9;

    byte[] getSupplementaryAttestationInfo(in Tag tag) = 10;

    boolean isOmkGrant(in @nullable CallerInfo ctx, in KeyDescriptor grant) = 13;
}
