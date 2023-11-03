package com.google.attestationexample.Registration;

import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.widget.TextView;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;
import java.security.MessageDigest;

import javax.security.auth.x500.X500Principal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.attestationexample.Constants;
import com.google.attestationexample.Registration.Internal.AndroidKeyAttestationStatement;
import com.google.attestationexample.Registration.Internal.AttestationObject;
import com.google.attestationexample.Registration.Internal.AttestedCredentialData;
import com.google.attestationexample.Registration.Internal.AuthenticatorData;
import com.google.attestationexample.Registration.Internal.CredentialPublicKeyEcdsa;
import com.google.attestationexample.Registration.Input.AuthenticatorSelectionCriteria;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialCreationOptions;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialParameters;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialRpEntity;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialUserEntity;
import com.google.attestationexample.Constants.CoseAlg;
import com.google.attestationexample.Registration.Internal.ClientData;
import com.google.attestationexample.Registration.Output.AuthenticatorAttestationResponseJSON;
import com.google.attestationexample.Registration.Output.RegistrationResponseJSON;

/**
 * AttestationTest generates an EC Key pair, with attestation, and displays the result in the
 * TextView provided to its constructor.
 */
public class AttestationTest extends AsyncTask<Void, String, Void> {
    private final TextView view;
    private final String packageName;

    public AttestationTest(TextView view, String packageName) {
        this.view = view;
        this.packageName = packageName;
    }

    @Override
    protected Void doInBackground(Void... params) {
        try {
            GenerateAndroidKeyAttestation();
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

    private void GenerateAndroidKeyAttestation() throws Exception {
        PublicKeyCredentialCreationOptions options = GenerateOptions();
        ClientData typedClientData = OptionsToClientData(options);
        byte[] clientDataJson = ClientDataToJson(typedClientData);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] clientDataHash = sha256.digest(clientDataJson);
        String keyUUID = UUID.fromString(Constants.keyUUID).toString();
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.deleteEntry(keyUUID);
        KeyPair keyPair = GenerateKey(keyUUID, clientDataJson);
        byte[] credentialId = keyUUID.getBytes(StandardCharsets.UTF_8);
        AuthenticatorData authenticatorData = GetAuthenticatorData(options.rp.id, credentialId, keyPair.getPublic());
        byte[] authData = authenticatorData.toByteArray();
        Signature signer = Signature.getInstance("SHA256WithECDSA");
        byte[] dataToSign = mergeByteArrays(authData, clientDataHash);
        signer.initSign(keyPair.getPrivate());
        signer.update(dataToSign);
        byte[] signature = signer.sign();
        AttestationObject attestationObject = CreateAttestationObject(keyStore, keyUUID, signature, authData);
        RegistrationResponseJSON registrationResponse = CreateRegistrationResponse(credentialId, attestationObject.toByteArray(), clientDataJson);
        String registrationResponseJson = RegistrationResponseToJson(registrationResponse);
        publishProgress(registrationResponseJson);
        System.out.println(registrationResponseJson);
    }

    private static String RegistrationResponseToJson(RegistrationResponseJSON registrationResponse) throws JsonProcessingException {
        ObjectWriter ow = new ObjectMapper().writer();
        String json = ow.writeValueAsString(registrationResponse);
        return json;
    }

    private static RegistrationResponseJSON CreateRegistrationResponse(byte[] credentialId, byte[] attestationObject, byte[] clientDataJSON) throws UnsupportedEncodingException {
        RegistrationResponseJSON result = new RegistrationResponseJSON();
        result.id = base64UrlEncode(credentialId);
        result.rawId = base64UrlEncode(credentialId);
        result.type = "public-key";
        result.response = CreateAuthenticatorAttestationResponse(attestationObject, clientDataJSON);
        return result;
    }

    private static AuthenticatorAttestationResponseJSON CreateAuthenticatorAttestationResponse(byte[] attestationObject, byte[] clientDataJSON) throws UnsupportedEncodingException {
        AuthenticatorAttestationResponseJSON result = new AuthenticatorAttestationResponseJSON();
        result.attestationObject = base64UrlEncode(attestationObject);
        result.clientDataJSON = base64UrlEncode(clientDataJSON);
        return result;
    }

    private static AttestationObject CreateAttestationObject(KeyStore keyStore, String keyUUID, byte[] signature, byte[] authData) throws CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException {
        AttestationObject result = new AttestationObject();
        result.attStmt = CreateAttestationStatement(keyStore, keyUUID, signature);
        result.authData = authData;
        return result;
    }

    private static AndroidKeyAttestationStatement CreateAttestationStatement(KeyStore keyStore, String keyUUID, byte[] signature) throws CertificateEncodingException, KeyStoreException {
        AndroidKeyAttestationStatement result = new AndroidKeyAttestationStatement();
        result.X5C = GetEncodedAttestationCertificates(keyStore, keyUUID);
        result.sig = signature;
        result.alg = CoseAlg.ES256;
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

    private static AuthenticatorData GetAuthenticatorData(String rpId, byte[] credentialId, PublicKey publicKey) throws NoSuchAlgorithmException {
        AuthenticatorData result = new AuthenticatorData();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        result.rpIdHash = sha256.digest(rpId.getBytes(StandardCharsets.UTF_8));
        byte flags = 0x00;
        // Bit 0: User Present (UP) result.
        // Bit 1: Reserved for future use (RFU1).
        // Bit 2: User Verified (UV) result.
        // Bit 3: Backup Eligibility (BE).
        // Bit 4: Backup State (BS).
        // Bit 5: Reserved for future use (RFU2).
        // Bit 6: Attested credential data included (AT).
        // Bit 7: Extension data included (ED).

        byte FLAG_UP = 0x01; // Bit 0: User Present (UP) result.
        byte FLAG_UV = 0x04; // Bit 2: User Verified (UV) result.
        byte FLAG_BE = 0x08; // Bit 3: Backup Eligibility (BE).
        byte FLAG_BS = 0x10; // Bit 4: Backup State (BS).
        byte FLAG_AT = 0x40; // Bit 6: Attested credential data included (AT).
        byte FLAG_ED = (byte) 0x80; // Extension data included (ED).

        flags = (byte) (flags | FLAG_UP);
        flags = (byte) (flags | FLAG_UV);
        flags = (byte) (flags | FLAG_AT);

        result.flags = flags;
        result.signCount = 0x00;
        result.attestedCredentialData = GetAttestedCredentialData(credentialId, publicKey);
        return result;
    }

    private static AttestedCredentialData GetAttestedCredentialData(byte[] credentialId, PublicKey publicKey) {
        AttestedCredentialData result = new AttestedCredentialData();
        result.aaguid = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        result.credentialId = credentialId;
        result.credentialPublicKey = GetCredentialPublicKey(publicKey);
        return result;
    }

    private static CredentialPublicKeyEcdsa GetCredentialPublicKey(PublicKey publicKey) {
        byte[] pubKeyBuffer = publicKey.getEncoded();
        byte[] x = Arrays.copyOfRange(pubKeyBuffer, pubKeyBuffer.length - 64, pubKeyBuffer.length - 32);
        byte[] y = Arrays.copyOfRange(pubKeyBuffer, pubKeyBuffer.length - 32, pubKeyBuffer.length);
        CredentialPublicKeyEcdsa result = new CredentialPublicKeyEcdsa();
        result.X = x;
        result.Y = y;
        return result;
    }

    private KeyPair GenerateKey(String keyUUID, byte[] clientData) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        String keyUUIDString = keyUUID;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] clientDataHash = sha256.digest(clientData);

        Date notBefore = new Date(1698931745000L);
        Date notAfter = new Date(1698931775000L);

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(keyUUIDString, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("prime256v1"))
                .setCertificateSubject(new X500Principal(String.format("CN=%s, OU=%s", keyUUID, this.packageName)))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(notBefore)
                .setCertificateNotAfter(notAfter)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(86400)
                .setAttestationChallenge(clientDataHash)
                .build();
        kpGenerator.initialize(spec);
        KeyPair kp = kpGenerator.generateKeyPair();
        return kp;
    }

    private static byte[] ClientDataToJson(ClientData clientData) throws JsonProcessingException {
        ObjectWriter ow = new ObjectMapper().writer();
        String json = ow.writeValueAsString(clientData);
        byte[] result = json.getBytes(StandardCharsets.UTF_8);
        return result;
    }

    private static ClientData OptionsToClientData(PublicKeyCredentialCreationOptions options) {
        ClientData result = new ClientData();
        result.challenge = options.challenge;
        result.origin = "https://" + options.rp.id;
        result.type = "webauthn.create";
        return result;
    }

    private static PublicKeyCredentialCreationOptions GenerateOptions() throws UnsupportedEncodingException {
        PublicKeyCredentialCreationOptions result = new PublicKeyCredentialCreationOptions();
        result.rp = GenerateOptionsRp();
        result.user = GenerateOptionsUser();
        result.challenge = base64UrlEncode(Constants.AttestationChallenge);
        result.pubKeyCredParams = GenerateOptionsPubKeyCredParams();
        result.timeout = 60000;
        result.attestation = "direct";
        result.authenticatorSelection = GenerateOptionsAuthenticatorSelectionCriteria();
        return result;
    }

    private static PublicKeyCredentialRpEntity GenerateOptionsRp() {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity();
        rp.id = Constants.rpId;
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
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private static String base64UrlEncode(byte[] input) throws UnsupportedEncodingException {
        String result = new String(Base64.encode(input, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_CLOSE | Base64.NO_WRAP), StandardCharsets.UTF_8).trim();
        return result;
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
}
