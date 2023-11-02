package com.google.attestationexample;

public final class Constants {
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
