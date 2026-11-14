# Publishing to Maven Central

Two artifacts are published under the `net.dublinux.redkite` group:

| Artifact | For |
| --- | --- |
| `net.dublinux.redkite:red-kite-maven-plugin` | The Maven plugin (`redkite:report`, `redkite:check`). A self-contained jar: RedKite's own modules and their dependencies are shaded in, so nothing else needs to be on Central. |
| `net.dublinux.redkite:red-kite-parent` | The parent POM the plugin inherits from. Central needs it to resolve the plugin's POM. |

The server is not on Central. It ships as a zip on the GitHub release (`release.yml`).

## One-time setup

1. Sign in to the [Central Portal](https://central.sonatype.com/) and make sure the `net.dublinux` namespace is verified for the account (the `net.dublinux.redkite` group sits under it). If it isn't, add the DNS TXT record the portal asks for.
2. Create a Central Portal user token.
3. Create a GPG key, publish its public key to a public keyserver, and keep the private key and passphrase safe.
4. Add four GitHub Actions secrets to the repository:
    - `MAVEN_CENTRAL_USERNAME` and `MAVEN_CENTRAL_PASSWORD`: the token's username and password, not the account password.
    - `GPG_PRIVATE_KEY`: the ASCII-armoured private key.
    - `GPG_PASSPHRASE`.

## Publish a release

1. Make sure `main` is clean and `mvn verify` passes.
2. Tag the release and push the tag (this also runs the GitHub release workflow):

    ```bash
    git tag vX.Y.Z
    git push origin vX.Y.Z
    ```

3. In the repository's **Actions** tab, run **Publish to Maven Central** with that tag. It sets the version from the tag, runs the tests, and uploads the signed parent POM and plugin jar (with sources and Javadoc jars) through the `release` profile.
4. Open [Central Portal deployments](https://central.sonatype.com/publishing/deployments), check the pending deployment, and publish it by hand. `autoPublish` is off on purpose: a published version can never be changed or deleted.
5. After Central finishes processing, check the artifacts under the new version.

## If publishing fails

- **Namespace error:** `net.dublinux` isn't verified for the account.
- **401/403:** the token secrets are wrong, or hold the account password instead of the user token.
- **Signature error:** the private key and passphrase secrets don't match, or the public key isn't on a keyserver.
- **Version already exists:** versions can't be overwritten; tag a new one.
