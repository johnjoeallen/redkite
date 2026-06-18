package com.redkite.git;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class GitWorkingCopyService {
    public WorkingCopyState inspect(Path repoRoot) {
        try {
            String branch = git(repoRoot, "branch", "--show-current");
            String head = git(repoRoot, "rev-parse", "HEAD");
            String status = git(repoRoot, "status", "--porcelain");
            return new WorkingCopyState(repoRoot.toAbsolutePath().normalize(), branch, head, status.isBlank(), hashEditableFiles(repoRoot));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to inspect git working copy", e);
        }
    }

    public void createBranch(Path repoRoot, String branchName, String startPoint) {
        try {
            git(repoRoot, "branch", branchName, startPoint);
            git(repoRoot, "checkout", branchName);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create local branch", e);
        }
    }

    public Map<String, String> hashEditableFiles(Path repoRoot) {
        try {
            Map<String, String> hashes = new LinkedHashMap<>();
            try (var stream = Files.walk(repoRoot)) {
                for (Path path : stream.filter(p -> p.getFileName().toString().equals("pom.xml")).sorted().toList()) {
                    hashes.put(repoRoot.relativize(path).toString().replace('\\', '/'), sha256(path));
                }
            }
            return hashes;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash editable files", e);
        }
    }

    private String git(Path repoRoot, String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.add("-C");
        command.add(repoRoot.toString());
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            output = reader.lines().reduce("", (a, b) -> a + (a.isEmpty() ? "" : "\n") + b).trim();
        }
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IllegalStateException(String.join(" ", command) + " failed: " + output);
        }
        return output;
    }

    private String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = Files.readAllBytes(path);
        byte[] hash = digest.digest(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
