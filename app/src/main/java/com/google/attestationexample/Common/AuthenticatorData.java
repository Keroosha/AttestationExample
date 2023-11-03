package com.google.attestationexample.Common;

import com.google.attestationexample.WebAuthnUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class AuthenticatorData {
    public byte[] rpIdHash;
    public byte flags;
    public int signCount;
    public AttestedCredentialData attestedCredentialData;

    public static AuthenticatorData create(String rpId, byte[] credentialId, PublicKey publicKey) throws NoSuchAlgorithmException {
        AuthenticatorData result = new AuthenticatorData();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        result.rpIdHash = sha256.digest(rpId.getBytes(StandardCharsets.UTF_8));
        byte flags = 0x00;
        // Bit 0: User Present (UP) result.
        // Bit 1: Reserved for future use (RFU1).
        // Bit 2: User Verified (UV) result.
        // Bit 3: Backup Eligibility (BE).
        // Bit 4: Backup State (BS).
        // Bit 5: Reserved for future use (RFU2).
        // Bit 6: Attested credential data included (AT).
        // Bit 7: Extension data included (ED).

        byte FLAG_UP = 0x01; // Bit 0: User Present (UP) result.
        byte FLAG_UV = 0x04; // Bit 2: User Verified (UV) result.
        byte FLAG_BE = 0x08; // Bit 3: Backup Eligibility (BE).
        byte FLAG_BS = 0x10; // Bit 4: Backup State (BS).
        byte FLAG_AT = 0x40; // Bit 6: Attested credential data included (AT).
        byte FLAG_ED = (byte) 0x80; // Extension data included (ED).

        flags = (byte) (flags | FLAG_UP);
        flags = (byte) (flags | FLAG_UV);
        flags = (byte) (flags | FLAG_AT);

        result.flags = flags;
        result.signCount = 0x00;
        result.attestedCredentialData = AttestedCredentialData.create(credentialId, publicKey);
        return result;
    }

    public static AuthenticatorData create(String rpId) throws NoSuchAlgorithmException {
        AuthenticatorData result = new AuthenticatorData();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        result.rpIdHash = sha256.digest(rpId.getBytes(StandardCharsets.UTF_8));
        byte flags = 0x00;
        // Bit 0: User Present (UP) result.
        // Bit 1: Reserved for future use (RFU1).
        // Bit 2: User Verified (UV) result.
        // Bit 3: Backup Eligibility (BE).
        // Bit 4: Backup State (BS).
        // Bit 5: Reserved for future use (RFU2).
        // Bit 6: Attested credential data included (AT).
        // Bit 7: Extension data included (ED).

        byte FLAG_UP = 0x01; // Bit 0: User Present (UP) result.
        byte FLAG_UV = 0x04; // Bit 2: User Verified (UV) result.
        byte FLAG_BE = 0x08; // Bit 3: Backup Eligibility (BE).
        byte FLAG_BS = 0x10; // Bit 4: Backup State (BS).
        byte FLAG_AT = 0x40; // Bit 6: Attested credential data included (AT).
        byte FLAG_ED = (byte) 0x80; // Extension data included (ED).

        flags = (byte) (flags | FLAG_UP);
        flags = (byte) (flags | FLAG_UV);
        flags = (byte) (flags | FLAG_AT);

        result.flags = flags;
        result.signCount = 0x00;
        result.attestedCredentialData = null;
        return result;
    }

    public byte[] toByteArray() {
        byte[] attestedCredentialDataBytes = new byte[]{};
        if (attestedCredentialData != null) {
            attestedCredentialDataBytes = attestedCredentialData.toByteArray();
        }
        byte[] result = new byte[rpIdHash.length + 1 + 4 + attestedCredentialDataBytes.length];
        int index = 0;
        for (int i = 0; i < rpIdHash.length; i++, index++) {
            result[index] = rpIdHash[i];
        }
        result[index] = flags;
        index++;
        byte[] signCountBytes = WebAuthnUtils.toUint32BigEndian(signCount);
        for (int i = 0; i < signCountBytes.length; i++, index++) {
            result[index] = signCountBytes[i];
        }
        for (int i = 0; i < attestedCredentialDataBytes.length; i++, index++) {
            result[index] = attestedCredentialDataBytes[i];
        }
        return result;
    }
}
