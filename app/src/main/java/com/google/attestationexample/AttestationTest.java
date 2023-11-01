package com.google.attestationexample;

import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.widget.TextView;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.Calendar;

import org.json.JSONArray;

import java.security.MessageDigest;

import javax.security.auth.x500.X500Principal;

import static android.security.keystore.KeyProperties.KEY_ALGORITHM_EC;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.attestationexample.Options.AuthenticatorSelectionCriteria;
import com.google.attestationexample.Options.PublicKeyCredentialCreationOptions;
import com.google.attestationexample.Options.PublicKeyCredentialParameters;
import com.google.attestationexample.Options.PublicKeyCredentialRpEntity;
import com.google.attestationexample.Options.PublicKeyCredentialUserEntity;

import com.google.attestationexample.Options.Constants.CoseAlg;
import com.google.attestationexample.Internal.ClientData;


/**
 * AttestationTest generates an EC Key pair, with attestation, and displays the result in the
 * TextView provided to its constructor.
 */
public class AttestationTest extends AsyncTask<Void, String, Void> {
    private final TextView view;
    public static String PACKAGE_NAME;

    AttestationTest(TextView view, String PACKAGE_NAME) {
        this.view = view;
        this.PACKAGE_NAME = PACKAGE_NAME;
    }

    @Override
    protected Void doInBackground(Void... params) {
        try {
            fidoSampleGenerator();
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

    private void fidoSampleGenerator() throws Exception {

        PublicKeyCredentialCreationOptions options = GenerateOptions();
        ClientData typedClientData = OptionsToClientData(options);
        String clientDataJson = ClientDataToJson(typedClientData);


        String keystoreAlias = "fidoTestKey";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] authDataBase = hexStringToByteArray("9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bdd4450000000028f37d2b92b841c4b02a860cef7cc034004101552f0265f6e35bcc29877b64176690d59a61c3588684990898c544699139be88e32810515987ea4f4833071b646780438bf858c36984e46e7708dee61eedcbd0");

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        keyStore.deleteEntry(keystoreAlias);

        byte[] clientData = this.hexStringToByteArray("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2254663635625336443574656d6832427776707471674250623235695a4452786a774335616e73393149494a447263724f706e57544b344c5667466a6555563447444d65343477385349354e735a737349585455764467222c226f726967696e223a2268747470733a5c2f5c2f776562617574686e2e6f7267222c22616e64726f69645061636b6167654e616d65223a22636f6d2e616e64726f69642e6368726f6d65227d");
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
        int i = 0;
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

        byte[] authData = mergeByteArrays(authDataBase, cosepk);
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

    private static String ClientDataToJson(ClientData clientData) throws JsonProcessingException {
        ObjectWriter ow = new ObjectMapper().writer();
        String json = ow.writeValueAsString(clientData);
        return json;
    }

    private static ClientData OptionsToClientData(PublicKeyCredentialCreationOptions options) {
        ClientData result = new ClientData();
        result.challenge = options.challenge;
        result.origin = options.rp.id;
        result.type = "webauthn.create";
        return result;
    }

    private static PublicKeyCredentialCreationOptions GenerateOptions() {
        PublicKeyCredentialCreationOptions result = new PublicKeyCredentialCreationOptions();
        result.rp = GenerateOptionsRp();
        result.user = GenerateOptionsUser();
        result.challenge = com.google.common.io.BaseEncoding.base64Url().encode(hexStringToByteArray("F234917AD286DF19DE11A8C47DE77FBE611BF54EDB5D9DB2AC172FCAD963F9C2"));
        result.pubKeyCredParams = GenerateOptionsPubKeyCredParams();
        result.timeout = 60000;
        result.attestation = "direct";
        result.authenticatorSelection = GenerateOptionsAuthenticatorSelectionCriteria();
        return result;
    }

    private static PublicKeyCredentialRpEntity GenerateOptionsRp() {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity();
        rp.id = "vanbukin-pc.local";
        rp.name = "Test Host";
        return rp;
    }

    private static PublicKeyCredentialUserEntity GenerateOptionsUser() {
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity();
        user.id = "AAAAAAAAAAAAAAAAAAAAAQ";
        user.name = "testuser";
        user.displayName = "Test User";
        return user;
    }

    private static ArrayList<PublicKeyCredentialParameters> GenerateOptionsPubKeyCredParams() {
        ArrayList<PublicKeyCredentialParameters> result = new ArrayList<>();
        result.add(GenerateOptionsPublicKeyCredentialParameters(CoseAlg.RS256));
        result.add(GenerateOptionsPublicKeyCredentialParameters(CoseAlg.ES256));
        return result;
    }

    private static PublicKeyCredentialParameters GenerateOptionsPublicKeyCredentialParameters(int value) {
        PublicKeyCredentialParameters result = new PublicKeyCredentialParameters();
        result.alg = value;
        result.type = "public-key";
        return result;
    }

    private static AuthenticatorSelectionCriteria GenerateOptionsAuthenticatorSelectionCriteria() {
        AuthenticatorSelectionCriteria result = new AuthenticatorSelectionCriteria();
        result.authenticatorAttachment = "platform";
        result.userVerification = "required";
        return result;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
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

    private KeyPair makeNewKeyPair(String algorithm, KeyGenParameterSpec spec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                "AndroidKeyStore");
        keyPairGenerator.initialize(spec);
        return keyPairGenerator.generateKeyPair();
    }
}
