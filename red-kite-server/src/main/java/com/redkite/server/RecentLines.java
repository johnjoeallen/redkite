package com.redkite.server;

import com.redkite.core.domain.*;
import java.util.ArrayList;
import java.util.List;

/** A bounded, thread-safe tail of the last few lines of some live process output — shared by
 *  {@link ApplyJob} and {@link ScanJob} so the "Applying changes" and "Analysing" overlays can
 *  each show a short scrolling log without ever needing their own scrollbar; older lines just
 *  fall off the front once {@link #MAX} is exceeded. */
final class RecentLines {
    private static final int MAX = 7;
    private final java.util.ArrayDeque<String> lines = new java.util.ArrayDeque<>();

    synchronized void append(String line) {
        lines.addLast(line);
        while (lines.size() > MAX) lines.removeFirst();
    }

    synchronized List<String> snapshot() {
        return new ArrayList<>(lines);
    }
}
