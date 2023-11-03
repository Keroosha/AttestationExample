package com.google.attestationexample.Common;

import com.google.attestationexample.Constants;
import com.upokecenter.cbor.CBORObject;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public class AndroidKeyAttestationStatement {
    public int alg;
    public byte[] sig;
    public byte[][] X5C;

    public static AndroidKeyAttestationStatement create(KeyStore keyStore, String keyUUID, byte[] signature) throws CertificateEncodingException, KeyStoreException {
        AndroidKeyAttestationStatement result = new AndroidKeyAttestationStatement();
        result.X5C = GetEncodedAttestationCertificates(keyStore, keyUUID);
        result.sig = signature;
        result.alg = Constants.CoseAlg.ES256;
        return result;
    }

    private static byte[][] GetEncodedAttestationCertificates(KeyStore keyStore, String keyUUID) throws KeyStoreException, CertificateEncodingException {
        Certificate[] certs = keyStore.getCertificateChain(keyUUID);
        byte[][] result = new byte[certs.length][];
        for (int i = 0; i < certs.length; i++) {
            byte[] encodedCert = certs[i].getEncoded();
            result[i] = encodedCert;
        }
        return result;
    }

    public CBORObject toCBOR() {
        CBORObject x5cCbor = CBORObject.NewArray();
        for (int i = 0; i < X5C.length; i++) {
            x5cCbor = x5cCbor.Add(X5C[i]);
        }
        CBORObject attestationStatement = com.upokecenter.cbor.CBORObject.NewMap()
                .Add("alg", alg)
                .Add("sig", sig)
                .Add("x5c", x5cCbor);
        return attestationStatement;
    }
}
