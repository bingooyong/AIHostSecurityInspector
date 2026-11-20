# Logging

Use structured records on stderr; stdout is the requested result only. Log stable event/error codes and operation outcome. Never log raw documents, tokens, passwords, private keys, full environment or process argv. Scan/host IDs are added only when actual scan work exists. Do not claim an audit ledger before durable append-only audit storage is implemented.
