package com.google.attestationexample.Internal;

import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;

public class AndroidKeyAttestationStatement {
    public int alg;
    public byte[] sig;
    public byte[][] X5C;

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
