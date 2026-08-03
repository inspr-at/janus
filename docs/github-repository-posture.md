# GitHub repository-posture App

The scheduled `repository-posture` workflow verifies the live controls that protect Janus releases and secret handling. Its default `GITHUB_TOKEN` cannot read secret-scanning alerts: GitHub's `security-events` workflow permission covers code-scanning alerts only.

## Why an App

A fine-grained personal access token has a selected expiry and GitHub does not expose an API that Janus can use to mint its replacement. A classic personal access token can be long-lived, but the scopes needed for this check also grant unrelated write access.

Use a repository-only GitHub App instead. Its private key is the stable credential; every workflow run automatically mints a new installation token that expires after one hour and is revoked when the job completes.

## App contract

Create a GitHub App named `Janus Repository Posture` with this exact boundary:

- installation owner: `inspr-at`
- installation repository: only `janus`
- repository permissions:
  - Administration: read-only
  - Secret scanning alerts: read-only
- every other repository, organization, and account permission: no access
- webhook: inactive

GitHub automatically grants Metadata/read. Administration/read permits the existing live repository settings and ruleset checks. Secret-scanning-alerts/read permits only the zero-open-alert assertion. None of these permissions authorize writes.

GitHub redacts a ruleset's bypass actors from identities that cannot write the ruleset. To preserve read-only access without creating a blind spot, the checker pins each protected ruleset's repository identity, numeric ID, and `updated_at` revision in addition to its visible conditions and rules. Any ruleset edit therefore blocks posture assurance until an administrator reviews the complete ruleset and deliberately updates the pinned revision.

After installing the App only on `janus`:

1. Store its client ID as the repository Actions variable `JANUS_POSTURE_APP_CLIENT_ID`.
2. Generate a private key and store the downloaded PEM directly as the repository Actions secret `JANUS_POSTURE_APP_PRIVATE_KEY`.

Do not paste the private key into chat, tickets, command arguments, logs, or repository files. The workflow asks GitHub for only the two read permissions even if the App is later misconfigured more broadly, and the official token action is pinned to an immutable commit.

## Verification

Run **repository-posture** with `workflow_dispatch`. A trusted result ends with:

```text
github_repository_posture=trusted value_returned=false
```

Missing App credentials fail before token creation with `reason=app_credential_missing`. API failures report only a symbolic endpoint label and safe HTTP class; response bodies and alert data are never printed.

The installation token rotates automatically on every run. Rotate the App private key manually only after suspected exposure or as part of a deliberate cryptographic-key rotation: add a new key, replace the repository secret, run the workflow, and delete the old key only after the replacement run is green.
