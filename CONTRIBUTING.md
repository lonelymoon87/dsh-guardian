# Contributing

This repository is an independent DeepSeek Harness plugin, not part of the official monorepo.

1. Open an issue before changing a deny rule, approval level, or redaction guarantee.
2. Include a safe contrast test for every dangerous-operation match to limit false positives.
3. Update runtime behavior, tests, the review skill, and bilingual documentation together.
4. Run `pnpm run check` and report only the commands actually run.

Never add credentials, raw security-review evidence, generated tarballs, or private repository content to a contribution.
