# dsh-guardian

[![CI](https://github.com/lonelymoon87/dsh-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/lonelymoon87/dsh-guardian/actions/workflows/ci.yml)
[![Latest DSH compatibility](https://github.com/lonelymoon87/dsh-guardian/actions/workflows/dsh-compatibility.yml/badge.svg)](https://github.com/lonelymoon87/dsh-guardian/actions/workflows/dsh-compatibility.yml)
[![Release](https://img.shields.io/github/v/release/lonelymoon87/dsh-guardian)](https://github.com/lonelymoon87/dsh-guardian/releases/latest)
[![License](https://img.shields.io/github/license/lonelymoon87/dsh-guardian)](./LICENSE)

Runtime dangerous-operation policy, canonical output redaction, and security-review workflow for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

The installable v0.1.1 release targets DSH 0.1.0-rc.6. npm publication is an optional future distribution channel.

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

## Install

The package currently targets DSH `0.1.0-rc.6` plugin APIs and Node.js `^22.19 || >=24`.

```sh
dsh plugin --profile default add https://github.com/lonelymoon87/dsh-guardian/releases/download/v0.1.1/dsh-guardian-0.1.1.tgz
```

The release tarball is prebuilt and needs no build allowance. A pinned source install is also supported:

```sh
dsh plugin --profile default add github:lonelymoon87/dsh-guardian#v0.1.1
```

The source install runs this package's `prepare` build. pnpm 10 and later reject it until the profile allowlists the exact package key printed by the failed command; apply that instruction and rerun the same `dsh plugin add` command.

To upgrade, rerun `dsh plugin add` with the newer release URL. To uninstall:

```sh
dsh plugin --profile default remove dsh-guardian
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

- The v0.1.1 tarball installs directly from its HTTPS release URL into a clean DSH profile.
- The packed bundle and pinned GitHub source install both appear in `dsh --dump-config`.
- CI covers Node 22.19 and Node 24; a scheduled workflow repeats the real install against `@deepseek-ai/dsh@latest`.
- Bugs and compatibility reports are tracked in [GitHub Issues](https://github.com/lonelymoon87/dsh-guardian/issues).

## License

[MIT](./LICENSE)
