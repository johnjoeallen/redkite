package com.redkite.maven;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EnforcerDetectorTest {

    @TempDir
    Path tempDir;

    private final EnforcerDetector detector = new EnforcerDetector();

    @Test
    void returnsNotConfiguredWhenNoPom() {
        assertEquals(EnforcerDetector.DetectionResult.NOT_CONFIGURED, detector.detect(tempDir));
    }

    @Test
    void returnsNotConfiguredWhenEnforcerAbsent() throws IOException {
        writePom(tempDir, """
                <project>
                  <groupId>com.example</groupId>
                  <artifactId>test</artifactId>
                  <version>1.0</version>
                  <build>
                    <plugins>
                      <plugin>
                        <artifactId>maven-compiler-plugin</artifactId>
                      </plugin>
                    </plugins>
                  </build>
                </project>
                """);
        assertEquals(EnforcerDetector.DetectionResult.NOT_CONFIGURED, detector.detect(tempDir));
    }

    @Test
    void returnsConfiguredNoRulesWhenEnforcerPresentNoConvergenceRules() throws IOException {
        writePom(tempDir, """
                <project>
                  <build>
                    <plugins>
                      <plugin>
                        <groupId>org.apache.maven.plugins</groupId>
                        <artifactId>maven-enforcer-plugin</artifactId>
                        <executions>
                          <execution>
                            <goals><goal>enforce</goal></goals>
                            <configuration>
                              <rules>
                                <requireMavenVersion><version>3.9</version></requireMavenVersion>
                              </rules>
                            </configuration>
                          </execution>
                        </executions>
                      </plugin>
                    </plugins>
                  </build>
                </project>
                """);
        assertEquals(EnforcerDetector.DetectionResult.CONFIGURED_NO_CONVERGENCE_RULES, detector.detect(tempDir));
    }

    @Test
    void detectsDependencyConvergenceRule() throws IOException {
        writePom(tempDir, """
                <project>
                  <build>
                    <plugins>
                      <plugin>
                        <artifactId>maven-enforcer-plugin</artifactId>
                        <executions>
                          <execution>
                            <goals><goal>enforce</goal></goals>
                            <configuration>
                              <rules>
                                <dependencyConvergence/>
                              </rules>
                            </configuration>
                          </execution>
                        </executions>
                      </plugin>
                    </plugins>
                  </build>
                </project>
                """);
        assertEquals(EnforcerDetector.DetectionResult.CONFIGURED_WITH_CONVERGENCE_RULES, detector.detect(tempDir));
    }

    @Test
    void detectsRequireUpperBoundDepsRule() throws IOException {
        writePom(tempDir, """
                <project>
                  <build>
                    <plugins>
                      <plugin>
                        <artifactId>maven-enforcer-plugin</artifactId>
                        <executions>
                          <execution>
                            <goals><goal>enforce</goal></goals>
                            <configuration>
                              <rules>
                                <requireUpperBoundDeps/>
                              </rules>
                            </configuration>
                          </execution>
                        </executions>
                      </plugin>
                    </plugins>
                  </build>
                </project>
                """);
        assertEquals(EnforcerDetector.DetectionResult.CONFIGURED_WITH_CONVERGENCE_RULES, detector.detect(tempDir));
    }

    @Test
    void detectsEnforcerInPluginManagement() throws IOException {
        writePom(tempDir, """
                <project>
                  <build>
                    <pluginManagement>
                      <plugins>
                        <plugin>
                          <artifactId>maven-enforcer-plugin</artifactId>
                          <configuration>
                            <rules>
                              <dependencyConvergence/>
                            </rules>
                          </configuration>
                        </plugin>
                      </plugins>
                    </pluginManagement>
                    <plugins>
                      <plugin>
                        <artifactId>maven-enforcer-plugin</artifactId>
                      </plugin>
                    </plugins>
                  </build>
                </project>
                """);
        // pluginManagement has the rule but isn't itself in <build><plugins>
        // The plugin is present (in both sections), rule is in pluginManagement
        assertEquals(EnforcerDetector.DetectionResult.CONFIGURED_WITH_CONVERGENCE_RULES, detector.detect(tempDir));
    }

    private static void writePom(Path dir, String content) throws IOException {
        Files.writeString(dir.resolve("pom.xml"), content);
    }
}
