package com.redkite.core.service;

import java.io.*;
import java.util.Base64;

public final class SerializationSupport {
    private SerializationSupport() {
    }

    public static String toBase64(Serializable value) {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bout)) {
            out.writeObject(value);
            out.flush();
            return Base64.getEncoder().encodeToString(bout.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize object", e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T fromBase64(String value, Class<T> type) {
        try (ByteArrayInputStream bin = new ByteArrayInputStream(Base64.getDecoder().decode(value));
             ObjectInputStream in = new ObjectInputStream(bin)) {
            Object obj = in.readObject();
            return (T) obj;
        } catch (IOException | ClassNotFoundException e) {
            throw new IllegalStateException("Failed to deserialize object", e);
        }
    }
}
