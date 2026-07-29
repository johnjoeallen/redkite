# Duplicate Dependencies

RedKite's conflict detection (see [Dependency Conflicts](dependency-conflicts.md)) is built around Maven Enforcer's `dependencyConvergence` and `requireUpperBoundDeps` rules — it reads the enforcer's own findings rather than re-implementing convergence analysis itself. To get the most out of it in a multi-module project, enable both:

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <executions>
        <execution>
            <id>enforce-dependency-rules</id>
            <goals>
                <goal>enforce</goal>
            </goals>
            <configuration>
                <rules>
                    <dependencyConvergence/>
                    <requireUpperBoundDeps/>
                </rules>
            </configuration>
        </execution>
    </executions>
</plugin>
```

When RedKite resolves a duplicate or conflicting dependency version, the updated project must build successfully, and — for a Spring Boot project — start successfully through `spring-boot:run`. Both checks use the Maven arguments and environment variables configured in [Build Validation](../projects/build-validation.md).

If your project doesn't have Maven Enforcer configured with these rules at all, RedKite's other analysis (updates, vulnerabilities, licenses) still works — you just won't get conflict findings or pin/exclusion recommendations, since there's no enforcer output for RedKite to read.
