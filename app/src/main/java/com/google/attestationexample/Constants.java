package com.google.attestationexample;

import org.bouncycastle.util.encoders.Hex;

import java.util.UUID;

public final class Constants {

    public static final String keyUUID = UUID.fromString("98f677be-0107-4384-a30c-8732b9d1b8b4").toString();

    public static final byte[] AttestationChallenge = Hex.decode("F234917AD286DF19DE11A8C47DE77FBE611BF54EDB5D9DB2AC172FCAD963F9C2");
    public static final byte[] AssertionChallenge = Hex.decode("9A6F3E2B7B091FA698D1BC662D1408568EB94CA0E13E23C3F3ADAC3AFC76DEC9");
    public static final String  rpId = "vanbukin-pc.local";

    public static final class CoseAlg {
        public static final int RS1 = -65535;
        public static final int RS512 = -259;
        public static final int RS384 = -258;
        public static final int RS256 = -257;
        public static final int PS512 = -39;
        public static final int PS384 = -38;
        public static final int PS256 = -37;
        public static final int ES512 = -36;
        public static final int ES384 = -35;
        public static final int ES256 = -7;
    }

    public static final class CoseKeyCommonParameter {
        public static final int kty = 1;
        public static final int alg = 3;
        public static final int crv = -1;
        public static final int x = -2;
        public static final int y = -3;
    }

    public static final class CoseKeyType {
        public static final int EC2 = 2;
        public static final int RSA = 3;
    }

    public static final class CoseEllipticCurve {
        public static final int P256 = 1;
        public static final int P384 = 2;
        public static final int P521 = 3;
    }

}
