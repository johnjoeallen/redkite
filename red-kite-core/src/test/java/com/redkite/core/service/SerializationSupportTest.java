package com.redkite.core.service;

import com.redkite.core.domain.ComponentCoordinate;
import org.junit.jupiter.api.Test;

import java.io.NotSerializableException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SerializationSupportTest {
    @Test
    void roundTripsSerializableValues() {
        ComponentCoordinate coordinate = new ComponentCoordinate("org.example", "lib");
        String encoded = SerializationSupport.toBase64(coordinate);
        assertTrue(encoded.matches("[A-Za-z0-9+/=]+"), encoded);
        assertEquals(coordinate, SerializationSupport.fromBase64(encoded, ComponentCoordinate.class));

        ArrayList<String> list = new ArrayList<>(List.of("a", "b"));
        assertEquals(list, SerializationSupport.fromBase64(SerializationSupport.toBase64(list), List.class));
    }

    @Test
    void unserializableContentFailsClearly() {
        class Holder implements Serializable {
            @SuppressWarnings("unused") final Object notSerializable = new Object();
        }
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> SerializationSupport.toBase64(new Holder()));
        assertEquals("Failed to serialize object", e.getMessage());
        assertInstanceOf(NotSerializableException.class, e.getCause());
    }

    @Test
    void corruptInputFailsClearly() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> SerializationSupport.fromBase64("AAAA", Object.class));
        assertEquals("Failed to deserialize object", e.getMessage());
    }
}
