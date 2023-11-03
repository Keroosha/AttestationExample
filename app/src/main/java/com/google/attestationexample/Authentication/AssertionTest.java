package com.google.attestationexample.Authentication;

import android.os.AsyncTask;
import android.widget.TextView;

import com.google.attestationexample.Authentication.Input.PublicKeyCredentialRequestOptions;
import com.google.attestationexample.Authentication.Output.AuthenticationResponseJSON;
import com.google.attestationexample.Common.AuthenticatorData;
import com.google.attestationexample.Common.ClientData;
import com.google.attestationexample.Constants;
import com.google.attestationexample.WebAuthnUtils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.UUID;

public class AssertionTest extends AsyncTask<Void, String, Void> {

    private final TextView view;

    public AssertionTest(TextView view) {
        this.view = view;
    }

    private static PublicKeyCredentialRequestOptions GenerateOptions() {
        PublicKeyCredentialRequestOptions result = new PublicKeyCredentialRequestOptions();
        result.challenge = WebAuthnUtils.base64UrlEncode(Constants.AssertionChallenge);
        result.rpId = Constants.rpId;
        return result;
    }

    private static ClientData OptionsToClientData(PublicKeyCredentialRequestOptions options) {
        ClientData result = new ClientData();
        result.challenge = options.challenge;
        result.origin = Constants.origin;
        result.type = "webauthn.get";
        return result;
    }

    @Override
    protected Void doInBackground(Void... params) {
        try {
            GenerateAndroidKeyAssertion();
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

    private void GenerateAndroidKeyAssertion() throws Exception {
        PublicKeyCredentialRequestOptions options = GenerateOptions();
        ClientData typedClientData = OptionsToClientData(options);
        byte[] clientDataJson = typedClientData.toJsonBytes();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] clientDataHash = sha256.digest(clientDataJson);
        String keyUUID = UUID.fromString(Constants.keyUUID).toString();
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyUUID, null);;
        byte[] credentialId = keyUUID.getBytes(StandardCharsets.UTF_8);
        AuthenticatorData authenticatorData = AuthenticatorData.create(options.rpId);
        byte[] authData = authenticatorData.toByteArray();
        Signature signer = Signature.getInstance("SHA256WithECDSA");
        byte[] dataToSign = WebAuthnUtils.mergeByteArrays(authData, clientDataHash);
        signer.initSign(privateKey);
        signer.update(dataToSign);
        byte[] signature = signer.sign();
        AuthenticationResponseJSON result = AuthenticationResponseJSON.create(
                credentialId,
                clientDataJson,
                authData,
                signature,
                Constants.UserHandle
        );
        String authenticationResponseJson = result.toJson();
        publishProgress(authenticationResponseJson);
        System.out.println(authenticationResponseJson);
    }
}
