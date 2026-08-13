# dsh-guardian

Runtime dangerous-operation policy, canonical output redaction, and security-review workflow for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

> Early development: the public repository is reserved, but the package has not yet been published to npm.

[简体中文](./README.zh-CN.md)

## MVP

- A `tools/pre-execute` waterfall classifies dangerous shell, SQL, and structured file-write arguments as `deny`, `ask`, or unchanged.
- `standard`, `strict`, and `permissive` profiles provide different approval levels while retaining non-negotiable deny rules.
- Custom regular-expression rules add deployment-specific `deny` or `ask` decisions.
- A `tools/post-execute` waterfall redacts common credentials from canonical JSON results, failures, rendered text, and block feedback.
- Consecutive text blocks are scanned as one stream so splitting a credential across blocks does not bypass redaction.
- `/security-review` loads a bundled, read-only security-review skill.

The MVP does not claim to be a process sandbox, authorization system, data-loss-prevention service, or substitute for the provider policies mounted below it.

## Policy behavior

The built-in rules deny recursive forced deletion of root or home paths, network-response pipes into shells, raw writes to `/dev`, and writes to `/etc`. Force pushes, destructive SQL, and other recursive forced deletions ask for approval. Strict mode additionally asks for `sudo`; permissive mode retains only deny rules.

Guardian always delegates through `next()`. When another policy listener returns a decision, the most restrictive result wins: `deny` outranks `ask`, which outranks `allow`.

## Redaction behavior

Built-in patterns cover AWS access-key IDs, GitHub tokens, `sk-` API keys, PEM private-key blocks, and common credential assignments. Redaction is applied to the canonical JSON value when one exists, preserving arrays, objects, numbers, booleans, and null values. This prevents Code Mode and downstream renderers from retaining an unredacted value behind safe-looking display text.

Logs contain only the tool name, match count, and redaction labels. The plugin does not append custom session events because the current external plugin API does not expose an ignorable event envelope; emitting a required unknown event would make old sessions unreadable after uninstall.

## Development install

The package currently targets DSH `0.1.0-rc.6` plugin APIs and Node.js `^22.19 || >=24`.

```sh
pnpm install
pnpm run check
npm pack
dsh plugin --profile default add ./dsh-guardian-0.1.0.tgz
```

## Configuration

```yaml
- id: guardian
  name: dsh-guardian
  config:
    profile: standard
    rules:
      - name: production-host
        pattern: production\\.internal
        action: ask
        reason: production target requires review
    redaction:
      enabled: true
      patterns:
        - label: internal-token
          pattern: INT_[A-Z0-9]{12}
```

Regular-expression flags may contain only `i`, `m`, `s`, and `u`. Invalid expressions and labels fail during plugin loading.

## Verification

The tests cover positive and negative cases for every built-in rule, structured paths, profile behavior, downstream policy composition, nested canonical values, custom credentials, block feedback, split text blocks, disabled redaction, command dispatch, and invalid configuration.

## License

[MIT](./LICENSE)
