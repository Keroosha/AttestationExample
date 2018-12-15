package com.google.attestationexample;

import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.regex.Pattern;
import java.util.Calendar;
import org.json.JSONArray;
import org.json.JSONException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import static android.security.keystore.KeyProperties.DIGEST_SHA256;
import static android.security.keystore.KeyProperties.KEY_ALGORITHM_EC;

/**
 * AttestationTest generates an EC Key pair, with attestation, and displays the result in the
 * TextView provided to its constructor.
 */
public class AttestationTest extends AsyncTask<Void, String, Void> {
    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;

    private static final int KEY_USAGE_BITSTRING_LENGTH = 9;
    private static final int KEY_USAGE_DIGITAL_SIGNATURE_BIT_OFFSET = 0;
    private static final int KEY_USAGE_KEY_ENCIPHERMENT_BIT_OFFSET = 2;
    private static final int KEY_USAGE_DATA_ENCIPHERMENT_BIT_OFFSET = 3;

    private static final int OS_MAJOR_VERSION_MATCH_GROUP_NAME = 1;
    private static final int OS_MINOR_VERSION_MATCH_GROUP_NAME = 2;
    private static final int OS_SUBMINOR_VERSION_MATCH_GROUP_NAME = 3;
    private static final Pattern OS_VERSION_STRING_PATTERN = Pattern
            .compile("([0-9]{1,2})(?:\\.([0-9]{1,2}))?(?:\\.([0-9]{1,2}))?(?:[^0-9.]+.*)?");

    private static final int OS_PATCH_LEVEL_YEAR_GROUP_NAME = 1;
    private static final int OS_PATCH_LEVEL_MONTH_GROUP_NAME = 2;
    private static final Pattern OS_PATCH_LEVEL_STRING_PATTERN = Pattern
            .compile("([0-9]{4})-([0-9]{2})-[0-9]{2}");

    private static final int KM_ERROR_INVALID_INPUT_LENGTH = -21;
    private final TextView view;
    public static String PACKAGE_NAME;
    AttestationTest(TextView view, String PACKAGE_NAME) {
        this.view = view;
        this.PACKAGE_NAME = PACKAGE_NAME;
    }

    private static final String GOOGLE_ROOT_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV"
                    + "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy"
                    + "ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B"
                    + "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS"
                    + "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7"
                    + "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj"
                    + "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq"
                    + "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ"
                    + "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O"
                    + "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg"
                    + "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi"
                    + "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M"
                    + "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E"
                    + "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um"
                    + "AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD"
                    + "VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO"
                    + "BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk"
                    + "Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD"
                    + "ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB"
                    + "Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m"
                    + "qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY"
                    + "DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm"
                    + "QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u"
                    + "JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD"
                    + "CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy"
                    + "ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD"
                    + "qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic"
                    + "MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1"
                    + "wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk\n"
                    + "-----END CERTIFICATE-----";

    @Override
    protected Void doInBackground(Void... params) {
        try {
            testEcAttestation();
        } catch (Exception e) {
            StringWriter s = new StringWriter();
            e.printStackTrace(new PrintWriter(s));
            publishProgress(s.toString());
        }
        return null;
    }

    @Override
    protected void onProgressUpdate(String... values) {
        for (String value : values) {
            view.append(value);
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private void testEcAttestation() throws Exception {
        String ecCurve = "secp256r1";
        int keySize = 256;
        byte[] challenge = "challenge".getBytes();
        String keystoreAlias = "test_key";

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        keyStore.deleteEntry(keystoreAlias);

        publishProgress("Generating key pair...");
        Date startTime = new Date(new Date().getTime() - 1000);
        Log.d("****", "Start Time is: " + startTime.toString());
        Date originationEnd = new Date(startTime.getTime() + ORIGINATION_TIME_OFFSET);
        Date consumptionEnd = new Date(startTime.getTime() + CONSUMPTION_TIME_OFFSET);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keystoreAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(ecCurve))
                .setDigests(DIGEST_SHA256)
                .setAttestationChallenge(challenge);
                //.setUserAuthenticationRequired(true)
                //.setUserAuthenticationValidityDurationSeconds(30);

        builder.setKeyValidityStart(startTime)
                .setKeyValidityForOriginationEnd(originationEnd)
                .setKeyValidityForConsumptionEnd(consumptionEnd);

        generateKeyPair(KEY_ALGORITHM_EC, builder.build());
        publishProgress("Key pair generated\n\n");

        Certificate certificates[] = keyStore.getCertificateChain(keystoreAlias);
        publishProgress("Retrieved certificate chain of length " + certificates.length + "\n");
        verifyCertificateSignatures(certificates);

        X509Certificate attestationCert = (X509Certificate) certificates[0];
        X509Certificate secureRoot = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(
                                GOOGLE_ROOT_CERTIFICATE.getBytes()));
        X509Certificate rootCert = (X509Certificate) certificates[certificates.length - 1];
        if (Arrays.equals(secureRoot.getEncoded(), rootCert.getEncoded())) {
            publishProgress(
                    "\nRoot certificate IS the Google root. This attestation is STRONG\n\n");
        } else {
            publishProgress(
                    "\nRoot certificate IS NOT the Google root. This attestation is WEAK\n\n");
        }
        printKeyUsage(attestationCert);

        Attestation attestation = new Attestation(attestationCert);
        publishProgress(attestation.toString() + "\n");

        Signature signer = Signature.getInstance("SHA256WithECDSA");
        KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");
        keystore.load(null);

        PrivateKey key = (PrivateKey) keystore.getKey(keystoreAlias, null);
        signer.initSign(key);
        signer.update("Hello".getBytes());
        signer.sign();
        publishProgress("\n\nSuccessfully generated signature\n");

        this.fidoSampleGenerator();
    }

    private void fidoSampleGenerator() throws Exception {
        String ecCurve = "secp256r1";
        int keySize = 256;
        String keystoreAlias = "fidoTestKey";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] authDataBase = hexStringToByteArray("9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bdd4450000000028f37d2b92b841c4b02a860cef7cc034004101552f0265f6e35bcc29877b64176690d59a61c3588684990898c544699139be88e32810515987ea4f4833071b646780438bf858c36984e46e7708dee61eedcbd0");

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        keyStore.deleteEntry(keystoreAlias);

        byte[] clientData     = this.hexStringToByteArray("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2254663635625336443574656d6832427776707471674250623235695a4452786a774335616e73393149494a447263724f706e57544b344c5667466a6555563447444d65343477385349354e735a737349585455764467222c226f726967696e223a2268747470733a5c2f5c2f776562617574686e2e6f7267222c22616e64726f69645061636b6167654e616d65223a22636f6d2e616e64726f69642e6368726f6d65227d");
        byte[] clientDataHash = digest.digest(clientData);

        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 10);

        publishProgress("Generating key pair...");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keystoreAlias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("prime256v1"))
                .setCertificateSubject(
                        new X500Principal(String.format("CN=%s, OU=%s",
                                keystoreAlias, PACKAGE_NAME)))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setKeyValidityStart(notBefore.getTime())
                .setKeyValidityEnd(notAfter.getTime())
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(30)
                .setAttestationChallenge(clientDataHash);

        KeyPair kp = makeNewKeyPair(KEY_ALGORITHM_EC, builder.build());
        publishProgress("Key pair generated\n\n");

        Certificate[] certarray = keyStore.getCertificateChain(keystoreAlias);

        String certArray[] = new String[certarray.length];
        int i=0;
        for (Certificate cert : certarray) {
            byte[] buf = cert.getEncoded();
            certArray[i] = new String(Base64.encode(buf, Base64.DEFAULT))
                    .replace("\n", "");
            i++;
        }

        JSONArray jarray = new JSONArray(certArray);
        String key_attestation_data = jarray.toString();

        Signature signer = Signature.getInstance("SHA256WithECDSA");


        byte[] pubkeybuffer = kp.getPublic().getEncoded();
        byte[] coeffx = Arrays.copyOfRange(pubkeybuffer, pubkeybuffer.length - 64, pubkeybuffer.length - 32);
        byte[] coeffy = Arrays.copyOfRange(pubkeybuffer, pubkeybuffer.length - 32, pubkeybuffer.length);
        byte[] cosepk = mergeByteArrays(hexStringToByteArray("a5010203262001215820"), coeffx, hexStringToByteArray("225820"), coeffy);

        byte[] authData      = mergeByteArrays(authDataBase, cosepk);
        byte[] signaturebase = mergeByteArrays(authData, clientDataHash);

        signer.initSign(kp.getPrivate());
        signer.update(signaturebase);
        byte[] signature = signer.sign();
        publishProgress("\nauthData ", bytesToHex(authData));
        System.out.println("\nauthData " + bytesToHex(authData));

        publishProgress("\nsignature ", bytesToHex(signature));
        System.out.println("\nsignature " + bytesToHex(signature));

        publishProgress("\nFIDO CERTIFICATES ", key_attestation_data);
        System.out.println("\nYOLOLOLOLO CERTIFICATES " + key_attestation_data);

        publishProgress("\n\nSuccessfully generated signature\n");
    }

    private byte[] mergeByteArrays(byte[]... arguments) {
        byte[] finalbytearr = new byte[0];
        for (int i = 0; i < arguments.length; ++i) {
            byte[] chunk = arguments[i];

            byte[] temparr = new byte[finalbytearr.length + chunk.length];
            System.arraycopy(finalbytearr, 0, temparr, 0, finalbytearr.length);
            System.arraycopy(chunk, 0, temparr, finalbytearr.length, chunk.length);

            finalbytearr = temparr;
        }

        return finalbytearr;
    }

    private void generateKeyPair(String algorithm, KeyGenParameterSpec spec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                "AndroidKeyStore");
        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }


    private KeyPair makeNewKeyPair(String algorithm, KeyGenParameterSpec spec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                "AndroidKeyStore");
        keyPairGenerator.initialize(spec);
        return keyPairGenerator.generateKeyPair();
    }

    private void verifyCertificateSignatures(Certificate[] certChain)
            throws GeneralSecurityException {

        for (Certificate cert : certChain) {
            final byte[] derCert = cert.getEncoded();
            final String pemCertPre = Base64.encodeToString(derCert, Base64.NO_WRAP);
            Log.e("****", pemCertPre);
        }

        for (int i = 1; i < certChain.length; ++i) {
            PublicKey pubKey = certChain[i].getPublicKey();
            try {
                certChain[i - 1].verify(pubKey);
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                    | NoSuchProviderException | SignatureException e) {
                throw new GeneralSecurityException("Failed to verify certificate "
                        + certChain[i - 1] + " with public key " + certChain[i].getPublicKey(), e);
            }
            if (i == certChain.length - 1) {
                // Last cert is self-signed.
                try {
                    certChain[i].verify(pubKey);
                } catch (CertificateException e) {
                    throw new GeneralSecurityException(
                            "Root cert " + certChain[i] + " is not correctly self-signed", e);
                }
            }
        }
        publishProgress("Certificate chain signatures are valid\n");
    }

    private void printKeyUsage(X509Certificate attestationCert) {
        publishProgress("Key usage:");
        if (attestationCert.getKeyUsage() == null) {
            publishProgress(" NONE\n");
            return;
        }
        if (attestationCert.getKeyUsage()[KEY_USAGE_DIGITAL_SIGNATURE_BIT_OFFSET]) {
            publishProgress(" sign");
        }
        if (attestationCert.getKeyUsage()[KEY_USAGE_DATA_ENCIPHERMENT_BIT_OFFSET]) {
            publishProgress(" encrypt_data");
        }
        if (attestationCert.getKeyUsage()[KEY_USAGE_KEY_ENCIPHERMENT_BIT_OFFSET]) {
            publishProgress(" encrypt_keys");
        }
        publishProgress("\n");
    }

    private void printRootOfTrust(Attestation attestation) {
        RootOfTrust rootOfTrust = attestation.getTeeEnforced().getRootOfTrust();
//        assertNotNull(rootOfTrust);
//        assertNotNull(rootOfTrust.getVerifiedBootKey());
//        assertTrue(rootOfTrust.getVerifiedBootKey().length >= 32);
//        assertTrue(rootOfTrust.isDeviceLocked());
//        assertEquals(KM_VERIFIED_BOOT_VERIFIED, rootOfTrust.getVerifiedBootState());
    }
}
