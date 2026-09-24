package com.redkite.server;

import com.redkite.core.domain.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The small hand-rolled JSON reading and writing the HTTP API needs (flat objects, string maps, arrays of flat objects). */
final class Json {
    private Json() {
    }

    static Map<String, String> parseJsonObject(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        if (json == null || json.isBlank()) return map;
        String s = json.strip();
        if (s.startsWith("{")) s = s.substring(1);
        if (s.endsWith("}")) s = s.substring(0, s.length() - 1);
        // Naive key-value parser for flat JSON objects with string values
        int i = 0;
        while (i < s.length()) {
            // Find key
            int kStart = s.indexOf('"', i);
            if (kStart == -1) break;
            int kEnd = s.indexOf('"', kStart + 1);
            if (kEnd == -1) break;
            String key = s.substring(kStart + 1, kEnd);
            // Find colon
            int colon = s.indexOf(':', kEnd + 1);
            if (colon == -1) break;
            // Find value
            int vStart = colon + 1;
            while (vStart < s.length() && s.charAt(vStart) == ' ') vStart++;
            if (vStart >= s.length()) break;
            String value;
            if (s.charAt(vStart) == '"') {
                int vEnd = vStart + 1;
                while (vEnd < s.length()) {
                    if (s.charAt(vEnd) == '\\') { vEnd += 2; continue; }
                    if (s.charAt(vEnd) == '"') break;
                    vEnd++;
                }
                value = s.substring(vStart + 1, vEnd)
                        .replace("\\\"", "\"").replace("\\n", "\n").replace("\\\\", "\\");
                map.put(key, value);
                i = vEnd + 1;
            } else {
                // non-string value (number/bool/null)
                int vEnd = vStart;
                while (vEnd < s.length() && s.charAt(vEnd) != ',' && s.charAt(vEnd) != '}') vEnd++;
                value = s.substring(vStart, vEnd).strip();
                if (!"null".equals(value)) map.put(key, value);
                i = vEnd + 1;
            }
        }
        return map;
    }

    static String parseJsonField(String json, String field) {
        if (json == null) return null;
        int idx = json.indexOf("\"" + field + "\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + field.length() + 2);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = q1 + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') break;
            sb.append(c);
        }
        return sb.toString();
    }

    static String parseJsonPath(String json) {
        if (json == null) return null;
        int idx = json.indexOf("\"path\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + 6);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = q1 + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') break;
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(++i);
                if (next == '"') sb.append('"');
                else if (next == '\\') sb.append('\\');
                else if (next == '/') sb.append('/');
                else if (next == 'n') sb.append('\n');
                else if (next == 'r') sb.append('\r');
                else if (next == 't') sb.append('\t');
                else sb.append(next);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Parse a flat JSON object whose keys and values are all strings, e.g. {"a/pom.xml":"content"}. */
    static String extractJsonValue(String json, String key) {
        if (json == null) return null;
        int keyIdx = json.indexOf("\"" + key + "\"");
        if (keyIdx < 0) return null;
        int colon = json.indexOf(':', keyIdx + key.length() + 2);
        if (colon < 0) return null;
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length()) return null;
        char opening = json.charAt(start);
        if (opening == '{') return extractBalanced(json, start, '{', '}');
        if (opening == '[') return extractBalanced(json, start, '[', ']');
        return null;
    }

    private static String extractBalanced(String json, int start, char open, char close) {
        int depth = 0;
        boolean inString = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') { i++; continue; }
                if (c == '"') inString = false;
            } else {
                if (c == '"') inString = true;
                else if (c == open) depth++;
                else if (c == close) { if (--depth == 0) return json.substring(start, i + 1); }
            }
        }
        return null;
    }

    static List<Map<String, String>> parseJsonObjectArray(String json, String key) {
        String array = extractJsonValue(json, key);
        if (array == null || array.length() < 2) return List.of();
        List<Map<String, String>> result = new java.util.ArrayList<>();
        int depth = 0;
        int objStart = -1;
        boolean inString = false;
        for (int i = 0; i < array.length(); i++) {
            char c = array.charAt(i);
            if (inString) {
                if (c == '\\') { i++; continue; }
                if (c == '"') inString = false;
            } else {
                if (c == '"') inString = true;
                else if (c == '{') { if (depth++ == 0) objStart = i; }
                else if (c == '}') { if (--depth == 0 && objStart >= 0) { result.add(parseJsonObject(array.substring(objStart, i + 1))); objStart = -1; } }
            }
        }
        return result;
    }

    static Map<String, String> parseJsonStringMap(String json) {
        Map<String, String> result = new LinkedHashMap<>();
        if (json == null || json.isBlank()) return result;
        int i = 0;
        while (i < json.length()) {
            int kq1 = json.indexOf('"', i);
            if (kq1 < 0) break;
            int kq2 = skipJsonString(json, kq1 + 1);  // position of closing quote
            String key = readJsonString(json, kq1 + 1);
            int colon = json.indexOf(':', kq2 + 1);
            if (colon < 0) break;
            int vq1 = json.indexOf('"', colon + 1);
            if (vq1 < 0) break;
            int vq2 = skipJsonString(json, vq1 + 1);  // position of closing quote
            String value = readJsonString(json, vq1 + 1);
            result.put(key, value);
            i = vq2 + 1;
        }
        return result;
    }

    /** Returns the index of the closing {@code "} for a JSON string starting at {@code from} (after the opening quote). */
    private static int skipJsonString(String json, int from) {
        for (int i = from; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\') { i++; continue; }
            if (c == '"') return i;
        }
        return json.length();
    }

    private static String readJsonString(String json, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') break;
            if (c == '\\' && i + 1 < json.length()) {
                char n = json.charAt(++i);
                switch (n) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    default -> sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    static String jsonStr(String value) {
        if (value == null) return "null";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }

    static String jsonStrArray(List<String> values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(jsonStr(values.get(i)));
        }
        return sb.append("]").toString();
    }
}
