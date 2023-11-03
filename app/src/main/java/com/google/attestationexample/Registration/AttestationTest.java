package com.google.attestationexample.Registration;

import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.widget.TextView;

import com.google.attestationexample.Common.AttestationObject;
import com.google.attestationexample.Common.AuthenticatorData;
import com.google.attestationexample.Common.ClientData;
import com.google.attestationexample.Constants;
import com.google.attestationexample.Constants.CoseAlg;
import com.google.attestationexample.Registration.Input.AuthenticatorSelectionCriteria;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialCreationOptions;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialParameters;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialRpEntity;
import com.google.attestationexample.Registration.Input.PublicKeyCredentialUserEntity;
import com.google.attestationexample.Registration.Output.RegistrationResponseJSON;
import com.google.attestationexample.WebAuthnUtils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;

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

    private static ClientData OptionsToClientData(PublicKeyCredentialCreationOptions options) {
        ClientData result = new ClientData();
        result.challenge = options.challenge;
        result.origin = Constants.origin;
        result.type = "webauthn.create";
        return result;
    }

    private static PublicKeyCredentialCreationOptions GenerateOptions() {
        PublicKeyCredentialCreationOptions result = new PublicKeyCredentialCreationOptions();
        result.rp = GenerateOptionsRp();
        result.user = GenerateOptionsUser();
        result.challenge = WebAuthnUtils.base64UrlEncode(Constants.AttestationChallenge);
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
        byte[] clientDataJson = typedClientData.toJsonBytes();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] clientDataHash = sha256.digest(clientDataJson);
        String keyUUID = UUID.fromString(Constants.keyUUID).toString();
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.deleteEntry(keyUUID);
        KeyPair keyPair = GenerateKey(keyUUID, clientDataJson);
        byte[] credentialId = keyUUID.getBytes(StandardCharsets.UTF_8);
        AuthenticatorData authenticatorData = AuthenticatorData.create(options.rp.id, credentialId, keyPair.getPublic());
        byte[] authData = authenticatorData.toByteArray();
        Signature signer = Signature.getInstance("SHA256WithECDSA");
        byte[] dataToSign = WebAuthnUtils.mergeByteArrays(authData, clientDataHash);
        signer.initSign(keyPair.getPrivate());
        signer.update(dataToSign);
        byte[] signature = signer.sign();
        AttestationObject attestationObject = AttestationObject.create(keyStore, keyUUID, signature, authData);
        RegistrationResponseJSON registrationResponse = RegistrationResponseJSON.create(credentialId, attestationObject.toByteArray(), clientDataJson);
        String registrationResponseJson = registrationResponse.toJson();
        publishProgress(registrationResponseJson);
        System.out.println(registrationResponseJson);
    }

    private KeyPair GenerateKey(String keyUUID, byte[] clientData) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        String keyUUIDString = keyUUID;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] clientDataHash = sha256.digest(clientData);

        Date notBefore = new Date(1698931745000L);
        Date notAfter = new Date(1698931775000L);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
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
        keyPairGenerator.initialize(spec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }
}
