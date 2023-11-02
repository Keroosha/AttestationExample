package com.google.attestationexample.Internal;

import java.io.IOException;

public class AttestedCredentialData {
    public byte[] aaguid;
    public byte[] credentialId;
    public CredentialPublicKeyEcdsa credentialPublicKey;

    public byte[] toByteArray() throws IOException {
        byte[] credentialPublicKeyBytes = credentialPublicKey.toByteArray();
        byte[] result = new byte[aaguid.length + 2 + credentialId.length + credentialPublicKeyBytes.length];
        int idx = 0;
        for (int i = 0; i < aaguid.length; i++, idx++) {
            result[idx] = aaguid[i];
        }

        byte[] credentialIdLength = BE_convert2Bytes(credentialId.length);
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

    private static byte[] BE_convert2Bytes(int src) {
        byte tgt[] = new byte[2];
        tgt[0] = (byte) (src >>> 8);
        tgt[1] = (byte) (src & 0xff);
        return tgt;
    }
}
