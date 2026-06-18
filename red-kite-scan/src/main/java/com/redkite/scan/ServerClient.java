package com.redkite.scan;

import com.redkite.core.service.SerializationSupport;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public final class ServerClient {
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    private ServerClient() {
    }

    public static <T> T post(String baseUrl, String path, Object body, Class<T> responseType) {
        try {
            String encoded = SerializationSupport.toBase64((java.io.Serializable) body);
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(encoded, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() >= 300) {
                throw new IllegalStateException("Request failed: " + response.body());
            }
            if (responseType == Void.class || response.body().isBlank()) {
                return null;
            }
            return SerializationSupport.fromBase64(response.body(), responseType);
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    public static <T> T get(String baseUrl, String path, Class<T> responseType) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET().build();
            HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() >= 300) {
                throw new IllegalStateException("Request failed: " + response.body());
            }
            return SerializationSupport.fromBase64(response.body(), responseType);
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }
}
