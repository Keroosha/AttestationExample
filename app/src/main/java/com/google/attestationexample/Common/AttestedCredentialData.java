package com.google.attestationexample.Common;

import com.google.attestationexample.WebAuthnUtils;

import java.security.PublicKey;

public class AttestedCredentialData {
    public byte[] aaguid;
    public byte[] credentialId;
    public CredentialPublicKeyEcdsa credentialPublicKey;

    public static AttestedCredentialData create(byte[] credentialId, PublicKey publicKey){
        AttestedCredentialData result = new AttestedCredentialData();
        result.aaguid = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        result.credentialId = credentialId;
        result.credentialPublicKey = CredentialPublicKeyEcdsa.create(publicKey);
        return result;
    }

    public byte[] toByteArray() {
        byte[] credentialPublicKeyBytes = credentialPublicKey.toByteArray();
        byte[] result = new byte[aaguid.length + 2 + credentialId.length + credentialPublicKeyBytes.length];
        int idx = 0;
        for (int i = 0; i < aaguid.length; i++, idx++) {
            result[idx] = aaguid[i];
        }

        byte[] credentialIdLength = WebAuthnUtils.toUint16BigEndian(credentialId.length);
        for (int i = 0; i < credentialIdLength.length; i++, idx++) {
            result[idx] = credentialIdLength[i];
        }

        for (int i = 0; i < credentialId.length; i++, idx++) {
            result[idx] = credentialId[i];
        }
        for (int i = 0; i < credentialPublicKeyBytes.length; i++, idx++) {
            result[idx] = credentialPublicKeyBytes[i];
        }
        return result;
    }
}
