package com.google.attestationexample.Authentication.Output;

import com.google.attestationexample.WebAuthnUtils;

public class AuthenticatorAssertionResponseJSON {
    public String clientDataJSON;
    public String authenticatorData;
    public String signature;
    public String userHandle;

    public static AuthenticatorAssertionResponseJSON create(
            byte[] clientDataJSON,
            byte[] authenticatorData,
            byte[] signature,
            byte[] userHandle) {
        AuthenticatorAssertionResponseJSON result = new AuthenticatorAssertionResponseJSON();
        result.clientDataJSON = WebAuthnUtils.base64UrlEncode(clientDataJSON);
        result.authenticatorData = WebAuthnUtils.base64UrlEncode(authenticatorData);
        result.signature = WebAuthnUtils.base64UrlEncode(signature);
        result.userHandle = WebAuthnUtils.base64UrlEncode(userHandle);
        return result;
    }
}
