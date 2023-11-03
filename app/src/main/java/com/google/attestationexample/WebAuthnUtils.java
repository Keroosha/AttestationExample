package com.google.attestationexample;

import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public final class WebAuthnUtils {
    public static String base64UrlEncode(byte[] input) {
        String result = new String(Base64.encode(input, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_CLOSE | Base64.NO_WRAP), StandardCharsets.UTF_8).trim();
        return result;
    }

    public static byte[] toUint16BigEndian(int src) {
        byte tgt[] = new byte[2];
        tgt[0] = (byte) (src >>> 8);
        tgt[1] = (byte) (src & 0xff);
        return tgt;
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

    public static byte[] mergeByteArrays(byte[]... arguments) {
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
