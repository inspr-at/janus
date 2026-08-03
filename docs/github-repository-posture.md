# GitHub repository-posture credential

The scheduled `repository-posture` workflow verifies the live controls that protect Janus releases and secret handling. Its default `GITHUB_TOKEN` cannot read secret-scanning alerts: GitHub's `security-events` workflow permission covers code-scanning alerts only.

## Credential contract

Store a fine-grained personal access token as the repository Actions secret `JANUS_REPOSITORY_POSTURE_TOKEN` with this exact boundary:

- resource owner: `inspr-at`
- repository access: only `janus`
- repository permissions:
  - Administration: read-only
  - Secret scanning alerts: read-only
- every other repository and organization permission: no access
- no account permissions

The Administration/read permission permits the existing live repository settings and ruleset checks. Secret-scanning-alerts/read permits only the zero-open-alert assertion. Neither permission authorizes writes.

Create and store the token through GitHub's web UI. Do not paste it into chat, tickets, command arguments, logs, or repository files. Set the generated value directly at **Janus → Settings → Secrets and variables → Actions → New repository secret**.

## Verification

Run **repository-posture** with `workflow_dispatch`. A trusted result ends with:

```text
github_repository_posture=trusted value_returned=false
```

Missing credentials fail before the live check with `reason=credential_missing`. API failures report only a symbolic endpoint label and safe HTTP class; response bodies and alert data are never printed.

Rotate the credential before its selected expiry, replace the repository secret in place, and run the workflow manually. Delete the superseded token only after the replacement run is green.
