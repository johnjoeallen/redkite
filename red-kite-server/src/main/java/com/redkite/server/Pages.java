package com.redkite.server;

import com.redkite.core.domain.*;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import static com.redkite.server.Http.*;

/** Page layout: the Thymeleaf shell, inline CSS/JS, the logo and the user's theme preference. */
final class Pages {
    private static final Logger LOGGER = Logger.getLogger(Pages.class.getName());
    static final String BRAND = "RedKite";

    static final String VERSION = Optional.ofNullable(RedKiteServerMain.class.getPackage().getImplementationVersion())
            .orElse("dev");

    static final Set<String> VALID_THEMES = Set.of("dark", "light", "ocean", "dusk", "forest", "ember");
    private final java.nio.file.Path prefsFile;
    private volatile String theme;
    private final TemplateEngine templateEngine;
    private final String inlineCss;
    private final String inlineJs;

    /** @param prefsFile where UI preferences (the theme) are read from and saved to */
    Pages(java.nio.file.Path prefsFile) throws IOException {
        this.prefsFile = prefsFile;
        this.theme = loadTheme();
        this.inlineCss = loadClasspathResource("static/styles.css");
        this.inlineJs = loadClasspathResource("static/scripts.js");
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCacheable(false);
        this.templateEngine = new TemplateEngine();
        this.templateEngine.setTemplateResolver(resolver);
    }

    private static String loadClasspathResource(String path) throws IOException {
        try (InputStream is = RedKiteServerMain.class.getClassLoader().getResourceAsStream(path)) {
            if (is == null) throw new IOException("Classpath resource not found: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    String renderPage(String templateName, String title, String subtitle, String bodyContent) {
        Context ctx = new Context();
        ctx.setVariable("brand", BRAND);
        ctx.setVariable("title", title);
        ctx.setVariable("subtitle", subtitle);
        ctx.setVariable("theme", theme);
        ctx.setVariable("inlineCss", inlineCss);
        ctx.setVariable("inlineJs", inlineJs);
        ctx.setVariable("bodyContent", bodyContent);
        return templateEngine.process(templateName, ctx);
    }

    private String loadTheme() {
        try {
            if (!java.nio.file.Files.exists(prefsFile)) return "dark";
            java.util.Properties p = new java.util.Properties();
            try (var r = java.nio.file.Files.newBufferedReader(prefsFile)) { p.load(r); }
            String t = p.getProperty("theme", "dark");
            return VALID_THEMES.contains(t) ? t : "dark";
        } catch (IOException e) {
            return "dark";
        }
    }

    void saveTheme(String t) {
        try {
            java.nio.file.Files.createDirectories(prefsFile.getParent());
            java.util.Properties p = new java.util.Properties();
            if (java.nio.file.Files.exists(prefsFile)) {
                try (var r = java.nio.file.Files.newBufferedReader(prefsFile)) { p.load(r); }
            }
            p.setProperty("theme", t);
            try (var w = java.nio.file.Files.newBufferedWriter(prefsFile)) { p.store(w, "RedKite preferences"); }
            this.theme = t;
        } catch (IOException e) {
            LOGGER.warning("Failed to save theme preference: " + e.getMessage());
        }
    }

    void handleLogo(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        byte[] bytes = logoSvgInline().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "image/svg+xml; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private String logoSvgInline() {
        try (var stream = getClass().getResourceAsStream("/redkite-icon.svg")) {
            if (stream != null) return new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
        // fallback geometric icon
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 128 128\" role=\"img\" aria-label=\"RedKite logo\">"
                + "<defs><linearGradient id=\"rk\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\"><stop offset=\"0%\" stop-color=\"#ff6b6b\"/><stop offset=\"100%\" stop-color=\"#e11d48\"/></linearGradient></defs>"
                + "<rect width=\"128\" height=\"128\" rx=\"28\" fill=\"#0f172a\"/>"
                + "<path d=\"M64 16 L104 58 L78 66 L64 112 L50 66 L24 58 Z\" fill=\"url(#rk)\"/>"
                + "<path d=\"M64 16 L64 112\" stroke=\"#ffe4e6\" stroke-width=\"4\" stroke-linecap=\"round\" opacity=\"0.9\"/>"
                + "<path d=\"M24 58 L64 66 L104 58\" fill=\"none\" stroke=\"#ffe4e6\" stroke-width=\"4\" stroke-linecap=\"round\" stroke-linejoin=\"round\" opacity=\"0.9\"/>"
                + "<circle cx=\"64\" cy=\"66\" r=\"6\" fill=\"#fff1f2\"/>"
                + "</svg>";
    }
}
