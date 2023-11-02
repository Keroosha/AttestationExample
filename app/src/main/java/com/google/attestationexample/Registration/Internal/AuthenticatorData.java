package com.google.attestationexample.Registration.Internal;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class AuthenticatorData {
    public byte[] rpIdHash;
    public byte flags;
    public int signCount;
    public AttestedCredentialData attestedCredentialData;

    public byte[] toByteArray() throws IOException {
        byte[] attestedCredentialDataBytes = attestedCredentialData.toByteArray();
        byte[] result = new byte[rpIdHash.length + 1 + 4 + attestedCredentialDataBytes.length];
        int index = 0;
        for (int i = 0; i < rpIdHash.length; i++, index++) {
            result[index] = rpIdHash[i];
        }
        result[index] = flags;
        index++;
        byte[] signCountBytes = toUint32BigEndian(signCount);
        for (int i = 0; i < signCountBytes.length; i++, index++) {
            result[index] = signCountBytes[i];
        }
        for (int i = 0; i < attestedCredentialDataBytes.length; i++, index++) {
            result[index] = attestedCredentialDataBytes[i];
        }
        return result;
    }


    public static byte[] toUint32BigEndian(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(value);
        if (!ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN)) {
            buffer.flip();
        }
        return buffer.array();
    }
}
