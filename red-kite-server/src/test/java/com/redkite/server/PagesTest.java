package com.redkite.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/** The page shell's theme preference: read at startup, saved on change, invalid values ignored. */
class PagesTest {
    @TempDir
    Path dir;

    private static String theme(Pages pages) {
        String html = pages.renderPage("home", "t", "s", "");
        int start = html.indexOf("data-theme=\"") + "data-theme=\"".length();
        return html.substring(start, html.indexOf('"', start));
    }

    @Test
    void themeDefaultsToDarkAndIsSavedAlongsideOtherPreferences() throws Exception {
        Path prefs = dir.resolve("prefs/redkite.properties");
        Pages pages = new Pages(prefs);
        assertEquals("dark", theme(pages));

        pages.saveTheme("ocean");
        assertEquals("ocean", theme(pages));
        assertEquals("ocean", theme(new Pages(prefs)), "the saved theme is read back at startup");

        Files.writeString(prefs, "other=kept\ntheme=forest\n");
        pages.saveTheme("dusk");
        String saved = Files.readString(prefs);
        assertTrue(saved.contains("other=kept"), saved);
        assertTrue(saved.contains("theme=dusk"), saved);
    }

    @Test
    void unknownOrUnreadableThemesFallBackToDark() throws Exception {
        Path prefs = dir.resolve("redkite.properties");
        Files.writeString(prefs, "theme=neon\n");
        assertEquals("dark", theme(new Pages(prefs)));

        Files.writeString(prefs, "unrelated=1\n");
        assertEquals("dark", theme(new Pages(prefs)));

        Path directory = Files.createDirectories(dir.resolve("a-directory"));
        assertEquals("dark", theme(new Pages(directory)), "a prefs path that can't be read as a file");
    }

    @Test
    void savingToAnUnwritableLocationKeepsTheCurrentTheme() throws Exception {
        Path blocker = Files.writeString(dir.resolve("blocker"), "");
        Pages pages = new Pages(blocker.resolve("prefs.properties"));
        pages.saveTheme("light");
        assertEquals("dark", theme(pages));
    }
}
