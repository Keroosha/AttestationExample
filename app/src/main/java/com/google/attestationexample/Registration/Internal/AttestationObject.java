package com.google.attestationexample.Registration.Internal;

import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;

import java.io.IOException;

public class AttestationObject {
    public AndroidKeyAttestationStatement attStmt;
    public byte[] authData;

    public byte[] toByteArray() {
        CBORObject androidKeyAttStmt = attStmt.toCBOR();
        CBORObject result = com.upokecenter.cbor.CBORObject.NewMap()
                .Add("fmt", "android-key")
                .Add("attStmt", androidKeyAttStmt)
                .Add("authData", authData);
        return result.EncodeToBytes(CBOREncodeOptions.DefaultCtap2Canonical);
    }
}
