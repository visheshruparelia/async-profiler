/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

package test.pmu;

import one.profiler.test.Arch;
import one.profiler.test.Output;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;

import one.profiler.test.Assert;
import one.profiler.test.Test;
import one.profiler.test.TestProcess;
import one.profiler.test.Os;

public class PmuTests {

    private void diagnosePerformanceCounterAccess() {
        try {
            // Check Java process capabilities
            String pid = String.valueOf(ProcessHandle.current().pid());
            Process process = Runtime.getRuntime().exec("getpcaps " + pid);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String caps = reader.readLine();
                System.out.println("Current process capabilities: " + caps);
            }

            // Check output directory permissions
            Path testDir = Paths.get("/tmp/");
            System.out.println("Test directory permissions:");
            System.out.println("Directory: " + testDir);
            System.out.println("Exists: " + Files.exists(testDir));
            if (Files.exists(testDir)) {
                System.out.println("Readable: " + Files.isReadable(testDir));
                System.out.println("Writable: " + Files.isWritable(testDir));
                System.out.println("Executable: " + Files.isExecutable(testDir));

                PosixFileAttributes attrs = Files.readAttributes(testDir, PosixFileAttributes.class);
                System.out.println("Owner: " + attrs.owner().getName());
                System.out.println("Group: " + attrs.group().getName());
                System.out.println("Permissions: " + PosixFilePermissions.toString(attrs.permissions()));
            }

        } catch (IOException e) {
            System.out.println("Error during diagnostics: " + e.getMessage());
            e.printStackTrace();
        }
    }


    @Test(mainClass = Dictionary.class, os = Os.LINUX)
    public void cycles(TestProcess p) throws Exception {
        try {
            diagnosePerformanceCounterAccess();
            System.out.println("Error file location: " + TestProcess.PROFERR);
            p.profile("-e cycles -d 3 -o collapsed -f %f");
            Output out = p.readFile("%f");
            System.out.println("output: " + out);
            double ratio16K = out.ratio("test/pmu/Dictionary.test16K");
            double ratio8M = out.ratio("test/pmu/Dictionary.test8M");
            System.out.println("Ratio 16K: " + ratio16K);
            System.out.println("Ratio 8M: " + ratio8M);
            Assert.isGreater(out.ratio("test/pmu/Dictionary.test16K"), 0.4);
            Assert.isGreater(out.ratio("test/pmu/Dictionary.test8M"), 0.4);
        } catch (Exception e) {
            System.out.println("Full exception: " + e);
            if (!p.readFile(TestProcess.PROFERR).contains("Perf events unavailable")) {
                throw e;
            }
        }
    }

    @Test(mainClass = Dictionary.class, os = Os.LINUX, arch = {Arch.X64, Arch.X86})
    public void cacheMisses(TestProcess p) throws Exception {
        try {
            p.profile("-e cache-misses -d 3 -o collapsed -f %f");

            Output out = p.readFile("%f");
            Assert.isLess(out.ratio("test/pmu/Dictionary.test16K"), 0.2);
            Assert.isGreater(out.ratio("test/pmu/Dictionary.test8M"), 0.8);
        } catch (Exception e) {
            if (!p.readFile(TestProcess.PROFERR).contains("Perf events unavailable")) {
                throw e;
            }
        }
    }

    @Test(mainClass = Dictionary.class, os = Os.MACOS)
    public void pmuIncompatible(TestProcess p) throws Exception {
        try {
            p.profile("-e cache-misses -d 3 -o collapsed -f %f");
            throw new AssertionError("PerfEvents should succeed on Linux only");
        } catch (IOException e) {
            assert p.readFile(TestProcess.PROFERR).contains("PerfEvents are not supported on this platform");
        }
    }
}
