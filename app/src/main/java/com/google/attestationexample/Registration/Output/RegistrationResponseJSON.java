package com.google.attestationexample.Registration.Output;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.attestationexample.WebAuthnUtils;

public class RegistrationResponseJSON {
    public String id;
    public String rawId;
    public AuthenticatorAttestationResponseJSON response;
    public String type;

    public static RegistrationResponseJSON create(byte[] credentialId, byte[] attestationObject, byte[] clientDataJSON) {
        RegistrationResponseJSON result = new RegistrationResponseJSON();
        result.id = WebAuthnUtils.base64UrlEncode(credentialId);
        result.rawId = WebAuthnUtils.base64UrlEncode(credentialId);
        result.type = "public-key";
        result.response = AuthenticatorAttestationResponseJSON.create(attestationObject, clientDataJSON);
        return result;
    }

    public String toJson() throws JsonProcessingException {
        ObjectWriter ow = new ObjectMapper().writer();
        String json = ow.writeValueAsString(this);
        return json;
    }
}
