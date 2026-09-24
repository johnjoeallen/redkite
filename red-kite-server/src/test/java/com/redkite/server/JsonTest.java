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

/** The hand-rolled JSON reading and writing. */
class JsonTest {
    // ---------------------------------------------------------------- JSON and form parsing

    @Test
    void parseJsonObjectHandlesStringsNumbersAndEscapes() {
        Map<String, String> m = Json.parseJsonObject(
                " {\"a\":\"x\\\"y\\\\z\\nw\", \"n\": 42, \"b\":true,\"z\":null,\"s\":  \"sp\"} ");
        assertEquals(Map.of("a", "x\"y\\z\nw", "n", "42", "b", "true", "s", "sp"), m);
        assertEquals(Map.of(), Json.parseJsonObject(null));
        assertEquals(Map.of(), Json.parseJsonObject("  "));
        assertEquals(Map.of(), Json.parseJsonObject("{\"dangling"));
        assertEquals(Map.of(), Json.parseJsonObject("{\"k\"}"));
        assertEquals(Map.of(), Json.parseJsonObject("{\"k\":"));
    }

    @Test
    void parseJsonFieldAndPath() {
        assertEquals("abc", Json.parseJsonField("{\"id\" : \"abc\"}", "id"));
        assertNull(Json.parseJsonField("{\"id\":1}", "id"));
        assertNull(Json.parseJsonField("{\"x\":\"1\"}", "id"));
        assertNull(Json.parseJsonField("{\"id\"", "id"));
        assertNull(Json.parseJsonField(null, "id"));
        assertEquals("unterminated", Json.parseJsonField("{\"id\":\"unterminated", "id"));

        assertEquals("C:\\dir\"/x\ny\rz\tq!", Json.parseJsonPath("{\"path\":\"C:\\\\dir\\\"\\/x\\ny\\rz\\tq\\!\"}"));
        assertNull(Json.parseJsonPath(null));
        assertNull(Json.parseJsonPath("{}"));
        assertNull(Json.parseJsonPath("{\"path\"}"));
        assertNull(Json.parseJsonPath("{\"path\":1}"));
    }

    @Test
    void extractJsonValueReturnsBalancedObjectsAndArrays() {
        String json = "{\"o\": {\"a\":\"}\\\"\",\"b\":{\"c\":1}}, \"arr\":[1,[2],\"]\"], \"s\":\"x\", \"open\":{";
        assertEquals("{\"a\":\"}\\\"\",\"b\":{\"c\":1}}", Json.extractJsonValue(json, "o"));
        assertEquals("[1,[2],\"]\"]", Json.extractJsonValue(json, "arr"));
        assertNull(Json.extractJsonValue(json, "s"));
        assertNull(Json.extractJsonValue(json, "open"));
        assertNull(Json.extractJsonValue(json, "missing"));
        assertNull(Json.extractJsonValue("{\"k\"", "k"));
        assertNull(Json.extractJsonValue("{\"k\":   ", "k"));
        assertNull(Json.extractJsonValue(null, "k"));
    }

    @Test
    void parseJsonObjectArrayReadsEachObject() {
        List<Map<String, String>> list = Json.parseJsonObjectArray(
                "{\"items\":[{\"a\":\"1\"},{\"b\":\"}{\\\"\"}, {\"c\":{\"nested\":1}}]}", "items");
        assertEquals(3, list.size());
        assertEquals(Map.of("a", "1"), list.get(0));
        assertEquals("}{\"", list.get(1).get("b"));
        assertEquals(List.of(), Json.parseJsonObjectArray("{\"items\":[]}", "items"));
        assertEquals(List.of(), Json.parseJsonObjectArray("{}", "items"));
    }

    @Test
    void parseJsonStringMapUnescapesKeysAndValues() {
        Map<String, String> m = Json.parseJsonStringMap(
                "{\"a/pom.xml\":\"<x a=\\\"1\\\">\\n\\t\\r\\/\\\\\\u\", \"k\\\"2\":\"v\"}");
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("a/pom.xml", "<x a=\"1\">\n\t\r/\\u");
        expected.put("k\"2", "v");
        assertEquals(expected, m);
        assertEquals(Map.of(), Json.parseJsonStringMap(null));
        assertEquals(Map.of(), Json.parseJsonStringMap(" "));
        assertEquals(Map.of(), Json.parseJsonStringMap("{\"k\"}"));
        assertEquals(Map.of(), Json.parseJsonStringMap("{\"k\":1}"));
    }

    @Test
    void jsonStringsAndArrays() {
        assertEquals("\"q\\\"b\\\\n\\nr\\rt\\t\"", Json.jsonStr("q\"b\\n\nr\rt\t"));
        assertEquals("null", Json.jsonStr(null));
        assertEquals("[\"a\",null]", Json.jsonStrArray(java.util.Arrays.asList("a", null)));
        assertEquals("[]", Json.jsonStrArray(List.of()));
    }
}
