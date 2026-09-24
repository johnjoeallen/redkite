package com.redkite.server;

import com.redkite.core.domain.*;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.redkite.server.Http.*;
import static com.redkite.server.Json.*;
import static com.redkite.server.Html.*;
import static com.redkite.server.CacheTtlSettings.*;
import static com.redkite.server.Pages.*;

/** The /config page and the APIs that save its settings and the theme preference. */
final class ConfigHandlers {
    private final Store store;
    private final Pages pages;

    ConfigHandlers(Store store, Pages pages) {
        this.store = store;
        this.pages = pages;
    }

    void handleApiPrefs(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        String t = parseJsonField(readBody(exchange), "theme");
        if (t == null || !VALID_THEMES.contains(t)) {
            sendText(exchange, 400, "Invalid theme");
            return;
        }
        pages.saveTheme(t);
        sendJson(exchange, 200, "{\"theme\":" + jsonStr(t) + "}");
    }

    void handleConfig(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        Map<String, String> values;
        try {
            values = store.loadConfigValues();
        } catch (SQLException e) {
            sendText(exchange, 500, BRAND + " error: " + escape(e.getMessage()));
            return;
        }
        StringBuilder body = new StringBuilder();
        body.append("<section class=\"card\">");
        body.append("<h2>About</h2>");
        body.append("<p class=\"muted\">").append(escape(BRAND)).append(" version ").append(escape(VERSION)).append("</p>");
        body.append("</section>");
        body.append("<section class=\"card\">");
        body.append("<h2>Cache TTLs</h2>");
        body.append("<p class=\"muted\">How long metadata lookups are cached before being refreshed. ")
                .append("Changes apply to the next lookup — no restart needed.</p>");
        body.append("<form method=\"POST\" action=\"/api/config\">");
        for (ConfigTtlEntry entry : CONFIG_TTL_ENTRIES) {
            String current = values.getOrDefault(entry.key(), Long.toString(entry.defaultValue().toMinutes()));
            body.append("<div class=\"config-row\">");
            body.append("<label for=\"").append(escape(entry.key())).append("\">").append(escape(entry.label())).append("</label>");
            body.append("<div class=\"config-row-input\">");
            body.append("<select id=\"").append(escape(entry.key())).append("\" name=\"").append(escape(entry.key())).append("\">");
            boolean matched = false;
            for (Map.Entry<Long, String> option : CONFIG_TTL_OPTIONS) {
                boolean selected = String.valueOf(option.getKey()).equals(current);
                if (selected) matched = true;
                body.append("<option value=\"").append(option.getKey()).append("\"").append(selected ? " selected" : "")
                        .append(">").append(escape(option.getValue())).append("</option>");
            }
            if (!matched) {
                // A previously-set value that isn't one of the presets (e.g. from before the
                // dropdown existed) — keep it selectable rather than silently changing it to the
                // nearest preset the moment this page loads.
                body.append("<option value=\"").append(escape(current)).append("\" selected>")
                        .append(escape(current)).append(" minutes (custom)</option>");
            }
            body.append("</select>");
            body.append("</div></div>");
        }
        body.append("<button class=\"button primary\" type=\"submit\">Save</button>");
        body.append("</form>");
        body.append("</section>");

        body.append("<section class=\"card\">");
        body.append("<h2>License permissiveness</h2>");
        body.append("<p class=\"muted\">Ranks licenses from most to least permissive (lower number = more permissive). ")
                .append("Used to highlight a dependency's most permissive declared license when it has more than one. ")
                .append("Add a name not listed yet to rank it too.</p>");
        body.append("<form method=\"POST\" action=\"/api/config/license-ranks\">");
        Map<String, Integer> ranks = store.loadLicenseRanks();
        List<Map.Entry<String, Integer>> sortedRanks = ranks.entrySet().stream()
                .sorted(Map.Entry.comparingByValue())
                .toList();
        int rowIndex = 0;
        for (Map.Entry<String, Integer> entry : sortedRanks) {
            body.append("<div class=\"config-row\">");
            body.append("<input type=\"hidden\" name=\"license_").append(rowIndex).append("\" value=\"").append(escape(entry.getKey())).append("\">");
            body.append("<label>").append(escape(entry.getKey())).append("</label>");
            body.append("<div class=\"config-row-input\"><input type=\"number\" name=\"rank_").append(rowIndex)
                    .append("\" value=\"").append(entry.getValue()).append("\" min=\"0\" style=\"width:80px\"></div>");
            body.append("</div>");
            rowIndex++;
        }
        body.append("<div class=\"config-row\">");
        body.append("<label for=\"license_new\">Add a license</label>");
        body.append("<div class=\"config-row-input\" style=\"display:flex;gap:8px\">");
        body.append("<input type=\"text\" id=\"license_new\" name=\"license_new\" placeholder=\"e.g. WTFPL\">");
        body.append("<input type=\"number\" name=\"rank_new\" placeholder=\"rank\" min=\"0\" style=\"width:80px\">");
        body.append("</div></div>");
        body.append("<button class=\"button primary\" type=\"submit\">Save</button>");
        body.append("</form>");
        body.append("</section>");

        sendHtml(exchange, 200, pages.renderPage("config", "Configuration", "Cache TTL settings", body.toString()));
    }

    void handleApiConfig(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        Map<String, String> form = parseForm(readBody(exchange));
        Set<String> validKeys = CONFIG_TTL_ENTRIES.stream().map(ConfigTtlEntry::key).collect(Collectors.toSet());
        try {
            for (Map.Entry<String, String> field : form.entrySet()) {
                if (!validKeys.contains(field.getKey())) continue;
                long minutes;
                try {
                    minutes = Long.parseLong(field.getValue().trim());
                } catch (NumberFormatException e) {
                    continue; // skip invalid entries rather than fail the whole save
                }
                if (minutes < 1) continue;
                store.updateConfigValue(field.getKey(), Long.toString(minutes));
            }
        } catch (SQLException e) {
            sendText(exchange, 500, BRAND + " error: " + escape(e.getMessage()));
            return;
        }
        sendRedirect(exchange, "/config");
    }

    void handleApiConfigLicenseRanks(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        Map<String, String> form = parseForm(readBody(exchange));
        try {
            int i = 0;
            while (form.containsKey("license_" + i)) {
                String name = form.get("license_" + i);
                String rankStr = form.get("rank_" + i);
                if (name != null && !name.isBlank() && rankStr != null) {
                    try {
                        store.updateLicenseRank(name.trim(), Integer.parseInt(rankStr.trim()));
                    } catch (NumberFormatException ignored) {
                        // skip an invalid entry rather than fail the whole save
                    }
                }
                i++;
            }
            String newName = form.get("license_new");
            String newRankStr = form.get("rank_new");
            if (newName != null && !newName.isBlank() && newRankStr != null && !newRankStr.isBlank()) {
                try {
                    store.updateLicenseRank(newName.trim(), Integer.parseInt(newRankStr.trim()));
                } catch (NumberFormatException ignored) {
                    // skip
                }
            }
        } catch (SQLException e) {
            sendText(exchange, 500, BRAND + " error: " + escape(e.getMessage()));
            return;
        }
        sendRedirect(exchange, "/config");
    }
}
