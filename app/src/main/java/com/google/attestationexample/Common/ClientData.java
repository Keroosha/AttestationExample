package com.google.attestationexample.Common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import java.nio.charset.StandardCharsets;

public class ClientData {
    public String type;
    public String challenge;
    public String origin;

    public byte[] toJsonBytes() throws JsonProcessingException {
        ObjectWriter ow = new ObjectMapper().writer();
        String json = ow.writeValueAsString(this);
        byte[] result = json.getBytes(StandardCharsets.UTF_8);
        return result;
    }
}
