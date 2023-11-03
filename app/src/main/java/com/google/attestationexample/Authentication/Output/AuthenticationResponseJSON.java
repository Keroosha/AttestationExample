package com.google.attestationexample.Authentication.Output;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.attestationexample.WebAuthnUtils;

public class AuthenticationResponseJSON {
    public String id;
    public String rawId;
    public AuthenticatorAssertionResponseJSON response;
    public String type;

    public static AuthenticationResponseJSON create(
            byte[] credentialId,
            byte[] clientDataJSON,
            byte[] authenticatorData,
            byte[] signature,
            byte[] userHandle) {
        AuthenticationResponseJSON result = new AuthenticationResponseJSON();
        result.id = WebAuthnUtils.base64UrlEncode(credentialId);
        result.rawId = WebAuthnUtils.base64UrlEncode(credentialId);
        result.response = AuthenticatorAssertionResponseJSON.create(clientDataJSON, authenticatorData, signature, userHandle);
        result.type = "public-key";
        return result;
    }

    public String toJson() throws JsonProcessingException {
        ObjectWriter ow = new ObjectMapper().writer();
        String json = ow.writeValueAsString(this);
        return json;
    }
}
