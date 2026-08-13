# dsh-guardian

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的运行时危险操作策略、规范结果脱敏和安全审查工作流。

> 目前处于早期开发阶段。公开仓库已经建立，npm 包尚未发布。

[English](./README.md)

## MVP

- 在 `tools/pre-execute` waterfall 中检查 shell、SQL 和结构化文件写入参数，返回 `deny`、`ask` 或保持原决策；
- 提供 `standard`、`strict` 和 `permissive` 三档策略，同时保留不可关闭的拒绝规则；
- 允许用正则表达式添加部署环境专属的 `deny` 或 `ask` 规则；
- 在 `tools/post-execute` waterfall 中对规范 JSON 结果、失败输出、渲染文本和拦截反馈做统一脱敏；
- 把连续文本块作为一段内容扫描，避免通过跨块拆分密钥绕过检测；
- `/security-review` 加载内置的只读安全审查技能。

本插件不是进程沙箱、授权系统或完整的数据防泄漏服务，也不会取代下游 provider 已有的安全策略。

## 策略行为

内置规则会拒绝对根目录或用户目录执行递归强制删除、把网络响应直接管道传给 shell、向 `/dev` 写入原始数据以及写入 `/etc`。强制推送、破坏性 SQL 和其他递归强制删除会要求审批。严格模式还会要求审批 `sudo`，宽松模式只保留拒绝规则。

Guardian 始终调用 `next()`。当其他策略监听器也返回决策时，插件保留更严格的结果，优先级依次为 `deny`、`ask`、`allow`。

## 脱敏行为

内置模式覆盖 AWS access key ID、GitHub token、`sk-` API key、PEM 私钥块和常见凭据赋值。存在规范 JSON 值时，插件优先脱敏该值，并保留数组、对象、数字、布尔值和 null 的结构。这样可以避免 Code Mode 或后续渲染器在安全显示文本背后继续持有未脱敏结果。

日志只记录工具名、匹配数量和脱敏标签，不记录秘密内容。插件不会追加自定义会话事件，因为当前外部插件 API 无法声明 ignorable 事件信封。写入必须识别的未知事件会导致用户卸载插件后无法读取旧会话。

## 开发安装

当前代码面向 DSH `0.1.0-rc.6` 插件 API，要求 Node.js `^22.19 || >=24`。

```sh
pnpm install
pnpm run check
npm pack
dsh plugin --profile default add ./dsh-guardian-0.1.0.tgz
```

## 配置

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

正则 flags 只允许 `i`、`m`、`s` 和 `u`。表达式或标签无效时，插件会在加载阶段明确失败。

## 许可证

[MIT](./LICENSE)
