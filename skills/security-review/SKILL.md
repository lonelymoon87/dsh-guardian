# Security Review

Review the current change set for exploitable security defects. Use the user's text after `/security-review` as scope or threat-model guidance.

1. Read repository security instructions, trust boundaries, and the changed diff. Prefer `git_status` and `git_diff` when available; otherwise use read-only Git commands through the shell tool.
2. Trace untrusted input through parsing, validation, authorization, filesystem, subprocess, network, persistence, and output paths. Do not infer safety from function names or comments.
3. Check for injection, missing authorization, secret exposure, SSRF, path traversal, unsafe deserialization, command execution, race conditions, insecure defaults, dependency risk, and fail-open error handling.
4. Check whether tests exercise the attack path at the boundary where hostile input enters.
5. If independent review agents are available, delegate distinct dimensions without duplicating the same scan. Verify their findings against source before including them.

Report only evidence-backed findings. Order them by severity. Each finding must include the affected path and line, the attacker-controlled input, the consequence, and a concrete remediation. Separate confirmed vulnerabilities from defense-in-depth suggestions. If no vulnerability is found, say so and list the high-risk paths you actually inspected plus any untested assumptions.

Do not modify files during the review unless the user explicitly requested fixes.
