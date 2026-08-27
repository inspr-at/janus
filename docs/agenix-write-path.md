# Agenix existing-value write path

When Janus already holds an approved value in process, it performs the agenix
encryption itself and writes a new name-derived ciphertext for the configured
public-key recipients. Existing ciphertext is never overwritten, operator
private keys are never used, and this path never returns or reveals the value.

New values remain a human step: the operator uses the encrypted agenix editor.
This write path does not add a value-bearing HTTP, CLI, or remote ingress.
