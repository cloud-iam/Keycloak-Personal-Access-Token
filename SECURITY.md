# Security policy

This extension issues credentials, so we take security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through
[GitHub private vulnerability reporting](https://github.com/cloud-iam/Keycloak-Personal-Access-Token/security/advisories/new).

Please include:

- the extension version and the Keycloak version
- the realm and client configuration needed to reproduce (an exported realm is ideal)
- the steps to reproduce, and what an attacker gains

## What happens next

1. We acknowledge your report within 3 business days.
2. We confirm the issue and agree on a fix and a disclosure date with you. We aim to release a fix within 30 days for serious issues.
3. We release the fix, then publish a GitHub security advisory (with a CVE when relevant). We credit you in the advisory unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes. The extension supports Keycloak 26.8.2 and later.

## Scope

In scope: anything that lets a token obtained with a Personal Access Token do more than the PAT's roles allow,
lets someone use, read or manage another user's PATs, or bypasses the checks described in the
[security model](README.md#security-model).

The [known limits](README.md#known-limits) listed in the README are documented behaviour, not vulnerabilities,
though better ideas to close them are welcome.
