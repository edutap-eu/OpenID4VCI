# Releasing

The version is not written down anywhere. `hatch-vcs` derives it from the git
tag, so tagging *is* setting the version, and the two cannot disagree.

## Steps

1. Make sure `main` is green and `CHANGES` reflect what is in the release.
2. Tag the commit and push the tag:

   ```shell
   git tag -a v1.0.0a1 -m "1.0.0a1"
   git push origin v1.0.0a1
   ```

3. Publish a GitHub release for that tag. Publishing the release — not pushing
   the tag — is what triggers the workflow.

## What happens then

`.github/workflows/release.yaml` builds the distribution and uploads it to
PyPI via Trusted Publishing.

There is no API token in this repository. PyPI verifies the workflow's OIDC
identity instead, which means there is no long-lived secret to leak, rotate or
forget.

## One-time setup on PyPI

Trusted Publishing has to be configured once, under the project's publishing
settings:

| Field | Value |
| --- | --- |
| Owner | `edutap-eu` |
| Repository | `OpenID4VCI` |
| Workflow | `release.yaml` |
| Environment | `pypi` |

The environment name must match the `environment:` key in the workflow. Until
this is configured, the publish step fails with a permissions error — which is
the intended behaviour, not a bug in the workflow.

## Version numbers

Semantic versioning. Pre-release segments follow PEP 440: `1.0.0a1`, `1.0.0b1`,
`1.0.0rc1`, then `1.0.0`.

While the credential format adapters are incomplete, releases stay in the
alpha range. Publishing early is still worth it: it is what lets
`edutap.wallet_google_identity` depend on this package normally, instead of
resolving it from a sibling checkout.
