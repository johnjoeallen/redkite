package com.redkite.server;

import com.redkite.core.domain.*;

/** HTML/JavaScript escaping and small reusable page fragments. */
final class Html {
    private Html() {
    }

    static String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    static String jsString(String value) {
        if (value == null) return "''";
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    static String scanOverlayHtml() {
        return "<div id=\"scan-overlay\" class=\"scan-overlay\" style=\"display:none\">"
             + "<div class=\"scan-overlay-box\">"
             + "<div style=\"display:flex;align-items:center;gap:10px\">"
             + "<img src=\"/logo.svg\" class=\"scan-spinner\" alt=\"\" />"
             + "<span>Analysing…</span>"
             + "</div>"
             + "<div id=\"scan-phases\" style=\"width:300px;display:flex;flex-direction:column;gap:10px\"></div>"
             + "<div id=\"scan-log-lines\" style=\"width:300px;height:8.4em;overflow:hidden;font-size:.72rem;"
             + "line-height:1.2em;font-family:ui-monospace,monospace;color:var(--muted);text-align:left\"></div>"
             + "</div></div>";
    }

    static String applyOverlayHtml() {
        // No "N / M" count is shown here: applying is a single atomic operation (validate, write
        // all changes, validate again), not a per-item loop, so there's no real item count to
        // track — a static "0 / 0" was previously shown here regardless of progress, which was
        // just wrong rather than merely uninformative. The progress bar instead reflects the
        // three real phases (pre-validate/applying/post-validate) reported by the apply job.
        return "<div id=\"apply-overlay\" class=\"scan-overlay\" style=\"display:none\">"
             + "<div class=\"scan-overlay-box\">"
             + "<div style=\"display:flex;align-items:center;gap:10px\">"
             + "<img src=\"/logo.svg\" class=\"scan-spinner\" alt=\"\" />"
             + "<span>Applying changes…</span>"
             + "</div>"
             + "<div class=\"scan-phase-track\" style=\"width:300px\">"
             + "<div id=\"apply-progress-bar\" class=\"scan-phase-fill active\" style=\"width:0%\"></div>"
             + "</div>"
             + "<div id=\"apply-progress-text\" style=\"font-size:.78rem;color:var(--muted);font-weight:400;"
             + "font-family:ui-monospace,monospace;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\"></div>"
             + "<div id=\"apply-log-lines\" style=\"width:300px;height:8.4em;overflow:hidden;font-size:.72rem;"
             + "line-height:1.2em;font-family:ui-monospace,monospace;color:var(--muted);text-align:left\"></div>"
             + "</div></div>";
    }

    /** One checkbox filter chip — a pill, not a button, since several can be active in the same
     *  group at once. {@code dataFilterValue} matches what {@code applyRemediationFilters} in
     *  scripts.js reads off each card's own {@code data-*} attributes for this group. */
    static String filterChipHtml(String group, String dataFilterValue, String label, long count) {
        return "<label class=\"filter-chip\"><input type=\"checkbox\" data-filter-group=\"" + group
                + "\" data-filter-value=\"" + dataFilterValue + "\" onchange=\"toggleFilterChip(this)\">"
                + "<span class=\"filter-chip-check\" aria-hidden=\"true\"></span>"
                + escape(label) + " <span class=\"tab-count\" data-chip-count=\"" + group + ":" + dataFilterValue + "\">"
                + count + "</span></label>";
    }

    static String statGrid(String... cards) {
        StringBuilder html = new StringBuilder("<div class=\"stat-grid\">");
        for (String card : cards) {
            html.append(card);
        }
        html.append("</div>");
        return html.toString();
    }

    static String statCard(String label, String value) {
        return "<div class=\"stat\"><div class=\"muted\">" + escape(label) + "</div><strong>" + escape(value) + "</strong></div>";
    }
}
