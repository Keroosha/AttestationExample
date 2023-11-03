package com.google.attestationexample.Registration.Output;

import com.google.attestationexample.WebAuthnUtils;

import java.io.UnsupportedEncodingException;

public class AuthenticatorAttestationResponseJSON {
    public String clientDataJSON;
    public String attestationObject;

    public static AuthenticatorAttestationResponseJSON create(byte[] attestationObject, byte[] clientDataJSON) {
        AuthenticatorAttestationResponseJSON result = new AuthenticatorAttestationResponseJSON();
        result.attestationObject = WebAuthnUtils.base64UrlEncode(attestationObject);
        result.clientDataJSON = WebAuthnUtils.base64UrlEncode(clientDataJSON);
        return result;
    }
}