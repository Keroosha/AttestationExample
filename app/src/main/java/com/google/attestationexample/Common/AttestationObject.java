package com.google.attestationexample.Common;

import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

public class AttestationObject {
    public AndroidKeyAttestationStatement attStmt;
    public byte[] authData;

    public static AttestationObject create(KeyStore keyStore, String keyUUID, byte[] signature, byte[] authData) throws CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException {
        AttestationObject result = new AttestationObject();
        result.attStmt = AndroidKeyAttestationStatement.create(keyStore, keyUUID, signature);
        result.authData = authData;
        return result;
    }

    public byte[] toByteArray() {
        CBORObject androidKeyAttStmt = attStmt.toCBOR();
        CBORObject result = com.upokecenter.cbor.CBORObject.NewMap()
                .Add("fmt", "android-key")
                .Add("attStmt", androidKeyAttStmt)
                .Add("authData", authData);
        return result.EncodeToBytes(CBOREncodeOptions.DefaultCtap2Canonical);
    }
}
