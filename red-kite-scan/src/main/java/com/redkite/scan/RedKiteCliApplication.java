package com.redkite.scan;

import com.redkite.core.domain.PlanApplicationResult;
import com.redkite.core.domain.PlannedFileChange;
import com.redkite.core.domain.ScanInput;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradePlan;
import com.redkite.core.service.PlanSafetyChecker;
import com.redkite.core.service.SerializationSupport;
import com.redkite.git.GitWorkingCopyService;
import com.redkite.maven.MavenProjectScanner;
import com.redkite.maven.PomEditor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

public class RedKiteCliApplication {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printHelp();
            return;
        }
        switch (args[0]) {
            case "scan" -> runScan(args);
            case "apply-plan" -> runApplyPlan(args);
            default -> printHelp();
        }
    }

    private static void runScan(String[] args) {
        Path repo = args.length > 1 && !args[1].startsWith("--") ? Path.of(args[1]) : Path.of(".");
        String server = option(args, "--server", "http://localhost:6502");
        boolean allowMajorUpgrades = hasFlag(args, "--allow-major");
        ScanInput input = new MavenProjectScanner(allowMajorUpgrades).scan(repo);
        ScanReport report = ServerClient.post(server, "/api/scans/input", input, ScanReport.class);
        System.out.println("Scan submitted: " + report.scanId());
        System.out.println(report.completenessMessage());
    }

    private static void runApplyPlan(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("apply-plan requires a plan id");
        }
        long planId = Long.parseLong(args[1]);
        Path repo = Path.of(option(args, "--repo", "."));
        String server = option(args, "--server", "http://localhost:6502");
        boolean yes = hasFlag(args, "--yes");

        UpgradePlan plan = ServerClient.get(server, "/api/upgrade-plans/" + planId, UpgradePlan.class);
        GitWorkingCopyService git = new GitWorkingCopyService();
        var state = git.inspect(repo);
        List<String> problems = PlanSafetyChecker.validate(
                repo,
                plan.baseBranchAtScanTime(),
                state.branch(),
                plan.baseHeadAtScanTime(),
                state.headCommit(),
                state.clean(),
                plan.expectedFileHashes(),
                state.fileHashes(),
                plan.plannedFileChanges());
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Plan safety checks failed: " + String.join(", ", problems));
        }

        System.out.println("Plan " + plan.id() + " -> branch " + plan.proposedBranchName());
        for (PlannedFileChange change : plan.plannedFileChanges()) {
            System.out.println(change.relativeFilePath() + ": " + change.oldVersion() + " -> " + change.newVersion());
        }
        if (!yes) {
            System.out.print("Proceed? [y/N] ");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String answer = reader.readLine();
            if (answer == null || !answer.trim().equalsIgnoreCase("y")) {
                System.out.println("Cancelled.");
                return;
            }
        }

        git.createBranch(repo, plan.proposedBranchName(), plan.baseHeadAtScanTime());
        PomEditor editor = new PomEditor();
        for (PlannedFileChange change : plan.plannedFileChanges()) {
            editor.applyChange(repo, change);
        }
        PlanApplicationResult result = new PlanApplicationResult(plan.id(), "APPLIED", "Plan applied locally", plan.proposedBranchName(), plan.plannedFileChanges().stream().map(PlannedFileChange::relativeFilePath).toList(), Instant.now());
        ServerClient.post(server, "/api/upgrade-plans/" + planId + "/application-result", result, Void.class);
        System.out.println("Applied locally; changes left uncommitted.");
    }

    private static String option(String[] args, String name, String defaultValue) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals(name)) {
                return args[i + 1];
            }
        }
        return defaultValue;
    }

    private static boolean hasFlag(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private static void printHelp() {
        System.out.println("red-kite scan <repo> [--server URL] [--allow-major]");
        System.out.println("red-kite apply-plan <planId> [--repo PATH] [--server URL] [--yes]");
    }
}
