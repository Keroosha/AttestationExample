package com.google.attestationexample.Registration.Internal;

import com.google.attestationexample.Constants;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;

import java.io.IOException;

public class CredentialPublicKeyEcdsa {

    public byte[] X;
    public byte[] Y;

    public byte[] toByteArray() throws IOException {
        CBORObject result = com.upokecenter.cbor.CBORObject.NewMap()
                .Add(Constants.CoseKeyCommonParameter.kty,Constants.CoseKeyType.EC2)
                .Add(Constants.CoseKeyCommonParameter.alg,Constants.CoseAlg.ES256)
                .Add(Constants.CoseKeyCommonParameter.crv,Constants.CoseEllipticCurve.P256)
                .Add(Constants.CoseKeyCommonParameter.x,X)
                .Add(Constants.CoseKeyCommonParameter.y,Y);


        return result.EncodeToBytes(CBOREncodeOptions.DefaultCtap2Canonical);
    }
}
