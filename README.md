# Passport Runtime

Python subprocess adapter with approval and operation recovery.

Version 0.1.0 is an AI-assisted engineering evaluation release, developed under one operator and assigned to this GitHub account. It is not evidence of independent human adoption, official Kite approval, Electric Capital inclusion or successful live payment.

## Run and verify

Python 3.11+ is required.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

This is a Python host adapter for an existing official CLI, not a wallet or a replacement Passport API. Construct Context with explicit owner/agent, existing working directory, the official credential file path, executable paths, operator-approved exact version strings and the SHA-256 of the installed kpass executable. No default versions are treated as payment-safe.

Runtime exposes inspect_runtime, discover, request_session, check_approval, accept_reuse, execute, resume_operation and activity. TargetRequest binds method, URL, body and merchant operation_id. Session bindings and both idempotency layers persist encrypted in SQLite. kpass argv always contains the explicit session and method; shell=False. A unique insert arbitrates concurrent purchase attempts.

After showing approval_url, hosts should call check_approval(operation_id, wait=True) once, then show Pending and require the user to indicate approval before another bounded check. Reuse requires explicit same-goal review. No next_command is executed. The first version supports one owner per official CLI context; separate users need independently verified OS/CLI contexts. Credential-file changes invalidate saved sessions.

The fixture CLI used in tests is not an approved real CLI version. Real version pinning, credentials, passkey approval and a funded session are still required.

## Configuration and recovery

The stored payment state UNKNOWN never means unpaid. Inspect the original receipt/activity and restricted journal; do not change an operation key to buy again. Where a writer lock survives a crash, stop all writer processes and review the journal before removing only the stale lock directory.

## Integration evidence

Read [compatibility.json](compatibility.json) and [the protocol boundary](docs/PROTOCOL.md). Local tests are E1; read-only public capability/RPC observations prove only the facts observed. Real Passport approval, funded purchase, SIWX interoperability, public deployment and catalog/EC review are not completed by this release. 

## Scope and evidence

[Original PRD](docs/PRD.md) describes the full target, not a claim that every external acceptance gate has passed. [Event contract](docs/EVENTS.md) defines the application records. The standalone repositories share protocol/storage support code, with distinct business implementations and tests. The license is MIT; third-party dependencies keep their upstream licenses. Reproduce failures without publishing payment signatures, account credentials or private files.
