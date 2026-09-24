package com.redkite.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Request parsing helpers. */
class HttpTest {
    @Test
    void formQueryAndIdListParsing() {
        assertEquals(Map.of("a b", "c&d", "e", ""), Http.parseForm("a+b=c%26d&e=&novalue&=x"));
        assertEquals(Map.of(), Http.parseForm(null));
        assertEquals(Map.of(), Http.parseForm(" "));
        assertEquals("v 1", Http.queryParam("x=1&k=v%201", "k"));
        assertNull(Http.queryParam("kk=1&=2", "k"));
        assertNull(Http.queryParam(null, "k"));
        assertEquals(Set.of(1L, 3L), Http.parseIdList(" 1, x,3"));
        assertEquals(Set.of(), Http.parseIdList(""));
        assertEquals(Set.of(), Http.parseIdList(null));
    }

    @Test
    void causeChainJoinsMessagesOrClassNames() {
        Exception e = new IllegalStateException("outer", new RuntimeException(new java.io.IOException("inner")));
        assertEquals("outer: java.io.IOException: inner: inner", Http.causeChain(e));
        assertEquals("NullPointerException", Http.causeChain(new NullPointerException()));
        assertEquals("unexpected failure", Http.causeChain(null));
    }
}
