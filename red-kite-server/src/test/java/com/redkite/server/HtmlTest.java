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

/** HTML and JavaScript escaping. */
class HtmlTest {
    // ---------------------------------------------------------------- escaping and output

    @Test
    void escapingForHtmlAndJavascript() {
        assertEquals("&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;", Html.escape("<a href=\"x\">&</a>"));
        assertEquals("", Html.escape(null));
        assertEquals("'it\\'s \\\\ here'", Html.jsString("it's \\ here"));
        assertEquals("''", Html.jsString(null));
    }
}
