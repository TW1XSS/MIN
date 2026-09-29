# Security Policy

MIN is an early-stage end-to-end encrypted messenger. The current branch is an
MVP/release-preparation branch, not a claim of audited production security.

## Reporting a vulnerability

Report privately through the public repository's **Security → Report a vulnerability**
form after the repository is published. If private reporting is not enabled yet,
contact the project owner through the private channel agreed for the repository and
ask for a secure address; do not put keys, exploit code, or personal data in a public
issue.

Please include:

- affected component and version/commit;
- reproducible steps or a minimal proof of concept;
- impact and required attacker position;
- logs or traces with secrets removed;
- whether the issue is already public.

Do not include real private keys, message plaintext, onion private keys, or another
person's data in the report.

## Safe harbor

Good-faith research is welcome when it:

- uses only accounts, relays, and devices you own or are authorised to test;
- avoids privacy violations, data destruction, persistence, and sustained DoS;
- does not access other users' messages, contacts, tokens, or metadata;
- does not exfiltrate, publish, or retain personal data;
- gives the project a reasonable time to fix the issue before disclosure.

We will not pursue legal action for research that follows these rules. This safe
harbor does not authorise testing third-party services or infrastructure.

## Internal automated security checks

The current MVP has internal automated checks for the following areas:

- PQXDH + Double Ratchet end-to-end encryption through pinned libsignal;
- strict CBOR/wire parsing and anti-replay protections;
- relay stores opaque ciphertext and minimal authentication state (mailbox id and token hash), not plaintext or client private keys;
- Tor/onion transport in the iOS client and loopback-only relay listener;
- Keychain storage for the local database key, backup exclusion, and fail-closed
  error handling;
- rate limiting, TTL, offline queue, RT-10 memory-dump and RT-11 TTL checks;
- relay restart auth-state persistence containing mailbox id and token hash only.

These checks are not a substitute for an independent external audit.
