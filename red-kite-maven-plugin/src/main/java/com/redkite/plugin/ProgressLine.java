package com.redkite.plugin;

import java.io.PrintStream;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Shows what the analysis is doing. On an interactive terminal it redraws a single status line
 * (spinner, current step, elapsed time) in place; anywhere else (CI, {@code -B}, redirected output,
 * {@code -X}) it logs each new phase once through {@code log}, so nothing is rewritten in a file.
 */
final class ProgressLine implements AutoCloseable {
    private static final String[] BRAILLE = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    private static final String[] ASCII = {"-", "\\", "|", "/"};
    private static final Pattern COUNTER = Pattern.compile("\\s+\\d+(/\\d+)?$");

    private final boolean interactive;
    private final PrintStream out;
    private final Consumer<String> log;
    private final String[] frames;
    private final long startNanos = System.nanoTime();
    private volatile String message = "Starting";
    private String lastPhase;
    private Thread ticker;

    ProgressLine(boolean interactive, PrintStream out, Consumer<String> log, boolean unicode) {
        this.interactive = interactive;
        this.out = out;
        this.log = log;
        this.frames = unicode ? BRAILLE : ASCII;
    }

    /** Whether to draw in place: a real terminal, Maven not in batch mode, not CI, and no debug logging. */
    static boolean shouldAnimate(boolean mavenInteractive, boolean debug, boolean terminal, String ci, String term) {
        return mavenInteractive && !debug && terminal && (ci == null || ci.isBlank()) && !"dumb".equals(term);
    }

    /** Detects a terminal on stdout; {@code Console.isTerminal()} exists from Java 22, earlier a console means a terminal. */
    static boolean stdoutIsTerminal() {
        java.io.Console console = System.console();
        if (console == null) return false;
        try {
            return (boolean) java.io.Console.class.getMethod("isTerminal").invoke(console);
        } catch (ReflectiveOperationException e) {
            return true;
        }
    }

    /** "Version 12/40" and "Version 13/40" are one phase, "Version". */
    static String phase(String message) {
        return COUNTER.matcher(message).replaceFirst("");
    }

    static String render(String frame, String message, long elapsedSeconds) {
        return frame + " " + message + " (" + elapsedSeconds + "s)";
    }

    void start() {
        if (!interactive) return;
        ticker = new Thread(() -> {
            int i = 0;
            while (!Thread.currentThread().isInterrupted()) {
                draw(frames[i++ % frames.length]);
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "redkite-progress");
        ticker.setDaemon(true);
        ticker.start();
    }

    void update(String text) {
        message = text;
        if (interactive) return;
        String phase = phase(text);
        if (!phase.equals(lastPhase)) {
            lastPhase = phase;
            log.accept(text);
        }
    }

    private synchronized void draw(String frame) {
        out.print("\r\u001B[2K" + render(frame, message, (System.nanoTime() - startNanos) / 1_000_000_000L));
        out.flush();
    }

    /** Stops the animation and clears its line, so later log output starts on a clean line. */
    @Override
    public void close() {
        if (ticker == null) return;
        ticker.interrupt();
        try {
            ticker.join(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        synchronized (this) {
            out.print("\r\u001B[2K");
            out.flush();
        }
        ticker = null;
    }
}
