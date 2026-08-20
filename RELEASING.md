# Releasing

Two destinations, and which one a build reaches is decided by *how* it was
triggered rather than by a flag anyone sets:

| Trigger | Goes to |
| --- | --- |
| every commit on `main` | `test.pypi.org` |
| a published GitHub release | `pypi.org` |

This is the arrangement the other eduTAP packages use, and the reason to keep
it is that the path to production gets exercised continuously. A release
workflow that only ever runs on release day is a workflow nobody has tested.

## The version is not written down

`hatch-vcs` derives it from the git tag, so tagging *is* setting the version
and the two cannot drift apart.

It also makes the per-commit uploads work: every commit on `main` produces a
distinct development version, and `test.pypi.org` rejects a version it has
already seen.

## Releasing to pypi.org

1. Make sure `main` is green.
2. Tag the commit and push the tag:

   ```shell
   git tag -a v1.0.0a1 -m "1.0.0a1"
   git push origin v1.0.0a1
   ```

3. Publish a GitHub release for that tag.

Publishing the release — not pushing the tag — is what uploads to `pypi.org`.

## One-time setup

Both indexes use Trusted Publishing, so there is no API token in this
repository to leak, rotate or forget. Each needs configuring once, and the
environment names must match the workflow:

| | Owner | Repository | Workflow | Environment |
| --- | --- | --- | --- | --- |
| pypi.org | `edutap-eu` | `OpenID4VCI` | `release.yaml` | `release-pypi` |
| test.pypi.org | `edutap-eu` | `OpenID4VCI` | `release.yaml` | `release-test-pypi` |

Until a publisher is configured, that upload step fails with a permissions
error. That is the intended behaviour rather than a fault in the workflow.

## Version numbers

Semantic versioning, with PEP 440 pre-release segments: `1.0.0a1`, `1.0.0b1`,
`1.0.0rc1`, then `1.0.0`.

While the credential format adapters are incomplete, releases stay in the
alpha range. Publishing early is still worth it: it is what lets
`edutap.wallet_google_identity` depend on this package normally, instead of
resolving it from a sibling checkout.
