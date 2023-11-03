package com.google.attestationexample.Common;

import com.google.attestationexample.Constants;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;

import java.security.PublicKey;
import java.util.Arrays;

public class CredentialPublicKeyEcdsa {

    public byte[] X;
    public byte[] Y;

    public static CredentialPublicKeyEcdsa create(PublicKey publicKey) {
        byte[] pubKeyBuffer = publicKey.getEncoded();
        byte[] x = Arrays.copyOfRange(pubKeyBuffer, pubKeyBuffer.length - 64, pubKeyBuffer.length - 32);
        byte[] y = Arrays.copyOfRange(pubKeyBuffer, pubKeyBuffer.length - 32, pubKeyBuffer.length);
        CredentialPublicKeyEcdsa result = new CredentialPublicKeyEcdsa();
        result.X = x;
        result.Y = y;
        return result;
    }

    public byte[] toByteArray() {
        CBORObject result = com.upokecenter.cbor.CBORObject.NewMap()
                .Add(Constants.CoseKeyCommonParameter.kty, Constants.CoseKeyType.EC2)
                .Add(Constants.CoseKeyCommonParameter.alg, Constants.CoseAlg.ES256)
                .Add(Constants.CoseKeyCommonParameter.crv, Constants.CoseEllipticCurve.P256)
                .Add(Constants.CoseKeyCommonParameter.x, X)
                .Add(Constants.CoseKeyCommonParameter.y, Y);
        return result.EncodeToBytes(CBOREncodeOptions.DefaultCtap2Canonical);
    }
}
