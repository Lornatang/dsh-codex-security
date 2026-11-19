---
description: "为 dsh profile 提供基于产物文件的安全审查能力：31 个 host 工具、16 个内置技能，以及一个把经过 schema 校验的扫描、发现、覆盖与导出封存在 profile 数据目录下的 Web 工作台。"
kind: "package-bundle"
---

# @lornatang/dsh-codex-security

[English](README.md) | 中文

## 概要

`dsh-codex-security` 为 dsh profile 增加一套可复现的安全审查流程。它注册 31 个 `codex_security_*` host 工具、16 个内置技能，以及 Web GUI 中的 Codex Security 区块，用于查看扫描、发现、覆盖情况与导出结果。`add` 命令向 profile 插入一条 patch 行，`remove` 命令将其移除。本包记录并校验 agent 提交的审查内容，也可自动协调相互独立的 Deep worker；它不执行目标代码，完成的扫描会在 profile 数据目录下封存不可变产物。

## 目录

- [使用本包](#use-this-package)
- [理解实现](#understand-the-implementation)
- [延伸阅读](#further-exploration)
- [模型体验](#model-experience)
- [已知限制与后续工作](#known-limitations-and-deferred-work)
- [开发者注记](#dev-note)

-----

<a id="use-this-package"></a>
## 使用本包

这一层为 agent 提供持久记录安全审查的位置，并为 profile 提供读取与导出结果的 Web 面板：每次扫描都会绑定目标、版本与范围，在对话轮次之间保留候选与验证记录，并在磁盘上封存一套经过 schema 校验的产物。

### 安装到 profile

```text
dsh plugin --profile <name> add @lornatang/dsh-codex-security
dsh plugin --profile <name> remove @lornatang/dsh-codex-security
```

安装 GitHub 上的 0.1.14 版本，请运行 `dsh plugin --profile <name> add https://github.com/Lornatang/dsh-codex-security/releases/download/v0.1.14/lornatang-dsh-codex-security-0.1.14.tgz`。

`add` 命令把这一层组合进 profile：profile 的 `cordis.patch.yml` 中新增一条 insert 条目，row id 为 `codex-security`，其 `config` 从本包默认值 `maxFiles: 5000`、`maxFileBytes: 1048576`、`defaultMode: standard` 开始；其余字段取 `src/config.ts` 中的默认值。包清单把 `dsh.bundle.patch` 指向该文档。`remove` 命令删除该条目，已经写入 profile 数据目录的扫描保持不变。

安装或移除后重启 DSH，因为该条目在 profile 启动时才会被组合。启动时插件会输出 `codex-security: registered 16 skills` 与 `codex-security: ready (state dir will resolve on first scan)`，Web GUI 的 Settings 中会出现 Codex Security 入口；不运行 Web 客户端的 profile 仍然会获得工具与技能。

新 profile 初始没有任何扫描。第一次访问存储的请求——工作台的状态请求或 `codex_security_inspect_setup`——会解析状态目录并创建 `<stateDir>/repositories/`；只有在某个 start 工具运行之后才会出现扫描记录，插件本身不会审查任何内容。

扫描位于 `<stateDir>/repositories/<repoKey>/scans/<scanId>/` 下：`repoKey` 是目标根路径 SHA-256 的前 16 个十六进制字符，`scanId` 是 `cs_` 加 24 个十六进制字符；`<stateDir>` 默认为 profile 的 `cordis.patch.yml` 同级的 `data/codex-security`（随 dsh 发布的 Web profile 即 `$DSH_HOME/profiles/web/data/codex-security`）。`scan.json` 保存绑定的目标、范围、清单、进度与 diff 列表；`index.json` 是可重建的列表缓存。完成扫描要求提交 `complete: true` 的草稿、至少一个覆盖面、每个候选与每个绑定 diff 文件的最终处置，以及未变化的快照摘要；随后插件按 `schemas/` 校验 findings、coverage 与 manifest 文档，把哈希记录进 `scan-manifest.json` 并封存扫描。已封存的产物不可修改，triage 单独存储且可继续编辑，导出默认写入 `<stateDir>/exports/<scanId>.<format>`。

重复使用默认路径导出时会增加数字后缀；显式指定的输出路径不能已存在。

### 本包提供的内容

本包在组合后的 profile 中拥有三个表面：31 个 host 工具、16 个技能，以及 Web GUI 中的一个工作台区块。[docs/TOOLS.md](docs/TOOLS.md) 记录了每个工具的参数与返回结构；[docs/CODEX-COMPATIBILITY.md](docs/CODEX-COMPATIBILITY.md) 说明与 Codex Security 的差异。

- **初始化与目标检查：** `codex_security_inspect_setup`、`codex_security_inspect_target`。
- **扫描生命周期：** `codex_security_start_scan`、`codex_security_start_standard_scan`、`codex_security_start_prompt_only_scan`、`codex_security_start_deep_scan`、`codex_security_resume_deep_scan`、`codex_security_get_deep_scan_status`、`codex_security_get_scan_context`、`codex_security_update_scan_context`、`codex_security_update_scan_progress`。
- **发现与候选：** `codex_security_record_discovery_candidates`、`codex_security_list_candidates`。
- **验证：** `codex_security_record_candidate_validations`、`codex_security_record_candidate_attack_paths`。
- **草稿与封存：** `codex_security_record_scan_draft`、`codex_security_complete_scan`、`codex_security_fail_scan`、`codex_security_cancel_scan`。
- **agent 产物：** `codex_security_save_artifact`、`codex_security_read_artifact`。
- **发现与分诊：** `codex_security_list_findings`、`codex_security_set_finding_triage`、`codex_security_set_finding_remediation`。
- **diff 审查：** `codex_security_prepare_review_items`、`codex_security_list_review_items`、`codex_security_update_review_item`。
- **查询与比较：** `codex_security_list_scans`、`codex_security_get_scan`、`codex_security_compare_scans`。
- **导出：** `codex_security_export_findings`。

技能目录新增 16 个条目，启动时分别从 `skills/<name>/SKILL.md` 加载，标记为 `source: bundled`，同时支持模型与用户调用：`security-scan`、`security-diff-scan`、`deep-security-scan`、`fix-finding`、`verify-fix`、`triage-finding`、`threat-model`、`track-findings`、`resolve-dependency-alert`、`vulnerability-writeup`、`assess-patch-risk`、`attack-path-analysis`、`define-security-policy`、`finding-discovery`、`propose-security-hardening`、`validation`；每个工作流的文本位于 [skills/](skills/)。

Web GUI 新增一条 `settings.section` 行，id 为 `codex-security`，order 为 41，label 为 Codex Security，由本包的客户端部分（`src/client/index.tsx`，发布为 `lib/client.js`）通过 `@deepseek-ai/dsh-client-ui-slots` 与 `@deepseek-ai/dsh-client-ui-settings` 注册。面板显示版本、解析后的状态目录以及扫描与发现数量；它按状态与时间列出扫描，并打开所选扫描的 Overview、Findings、Coverage 与 Artifacts & exports 面板，其中包含 triage 选择器以及 SARIF、JSON、CSV、Markdown 下载链接。面板通过 `/plugins/codex-security` 下的 HTTP 路由读取同一个服务。

### 配置

本包已带上下面这条条目，因此 profile 只写与默认值不同的部分：profile 自己的条目在层之后应用，优先生效。loader 按 `src/config.ts` 校验每个字段，非法值在启动时直接报错，而不会退化为默认值。

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: codex-security
  config:
    maxFiles: 5000
    maxFileBytes: 1048576
    defaultMode: standard
    failOnSeverity: high
    allowExportOutsideWorkspace: false
    maxScanAgeDays: 30
    deepWorkers: 4
    deepMaxDiscoveryRuns: 40
    # stateDir: /var/lib/dsh/codex-security
```

| 字段 | 默认值 | 含义 |
|---|---|---|
| `stateDir` | 空 | 保存扫描与导出的目录。为空时解析为 profile 的 `cordis.patch.yml` 同级的 `data/codex-security`；没有 profile patch 路径时解析为 `$DSH_HOME/profiles/web/data/codex-security`。 |
| `maxFiles` | `5000` | 每个目标纳入清单的文件数，1–200000；被截断时记录为扫描警告。 |
| `maxFileBytes` | `1048576` | 可审查清单的单文件大小上限，1024–67108864 字节。 |
| `defaultMode` | `standard` | `codex_security_start_scan` 使用的模式：`standard`、`prompt-only` 或 `deep`。 |
| `failOnSeverity` | `high` | 策略门槛：`informational`、`low`、`medium`、`high`、`critical` 或 `off`。 |
| `allowExportOutsideWorkspace` | `false` | 允许导出到状态目录、进程工作目录与目标根路径之外。 |
| `maxScanAgeDays` | `30` | 工作台把扫描标记为超出策略窗口的天数，1–3650 天。 |
| `deepWorkers` | `4` | Deep 并发 worker 上限，1–32。 |
| `deepMaxDiscoveryRuns` | `40` | Deep 最大发现尝试次数，1–10000。 |

### 自动 Deep 扫描

调用 `codex_security_start_deep_scan` 启动独立 worker，并妥善保管返回的 `recoveryClaim`。使用 `codex_security_get_deep_scan_status` 查看进度；进程退出后可调用 `codex_security_resume_deep_scan` 恢复。原会话可不提供凭据，其他会话恢复或取消时必须提供。`workers`、`maxDiscoveryRuns`、`stopAfterNoNew` 和 `maxTimeMinutes` 限制并发、尝试次数、无新发现轮数与时间；中断的尝试仍消耗次数。目标目录对象在启动时绑定，文件内容在异步初始化阶段绑定。配置的 DSH 模型服务会接收源码，可能使用网络。

自动模式需要本地 DSH `spawn` provider、agent-preset registry、原生执行器和匹配平台的可选文件系统二进制。标准 Web profile 提供前三项；缺失时会安全失败。自动 Deep 支持仓库或目录快照，不支持 diff；可设置 `manual: true` 使用手动流程。worker 只能读取验证过的绑定源码分块并提交结构化结果。零发现结果要求至少一个完整 worker 收到所有文件；读取回执只能证明内容已送达。

-----

<a id="understand-the-implementation"></a>
## 理解实现

<details>
<summary>实现内部 — 点击展开</summary>

这一层只有一条 patch 行：`insert` 一条 id 为 `codex-security`、包名为 `@lornatang/dsh-codex-security`、带三个配置值的条目。host 侧没有任何平台门控；清单中的 `dsh.client.platform: web` 只约束客户端 bundle，host 插件会在任何注入所需服务的 profile 中注册工具与技能。

Cordis 必须先注入 `tools` 与 `skills`，`apply` 才会运行。`apply` 使用解析后的配置与 profile patch 路径构建 `SecurityService`，然后分别注册 31 个工具、从 `skills/*/SKILL.md` 发现并注册16 个内置技能、绑定可选的 HTTP 路由，每一项都在可释放的 effect 中执行。启动时不会创建状态目录；`ScanStore.init` 在第一次访问存储时创建它。

start 工具解析目标、绑定版本或 diff 事实、在限额内建立可审查文件清单、计算快照摘要，并在扫描目录下写入 `scan.json`。后续工具追加草稿、候选、验证、攻击路径、审查条目与已保存产物，每次扫描的队列会串行化这些修改。完成时重新解析目标、拒绝已变化的摘要、检查草稿与覆盖约定、构建 findings、coverage、SARIF 与 Markdown 文档，按内置 schema 校验 findings、coverage 与 manifest 文档，并写入封存该扫描的 manifest。

工作台通过 `/plugins/codex-security` 下的 `handleRequest` 访问同一个服务，路由在存在 `webServer` 或 `httpServer` 时注册。客户端部分单独编译为 CommonJS 并为 DSH 模块加载器封装；它注入 `settings.section` 并请求这些路由。协调器通过配置的 DSH 模型服务派发隔离的静态审查 worker；模型服务可能使用网络，worker 不能执行目标代码。

SQLite 操作系统锁跨进程串行化协调器归属、扫描修改与索引更新；JSON 使用同目录原子替换。共享状态需要可信本地目录和可靠的 SQLite 文件锁；单个文件原子写入，但完整封存不是单个事务。

| 源码 | 内容 |
|---|---|
| `cordis.patch.yml` | 这一层：一条 insert 条目，row id `codex-security`，三个配置默认值。 |
| `src/index.ts` | host 入口：`apply`、配置导出、内置技能的发现与注册。 |
| `src/config.ts` | `Config` 接口、`DEFAULT_CONFIG`，以及启动时执行的 schema 范围。 |
| `src/constants.ts` | 包名与插件名、版本、路由前缀、工具与技能名称清单。 |
| `src/service.ts` | 扫描生命周期：目标绑定、草稿、验证、封存、发现、导出与比较。 |
| `src/store.ts` | 状态目录解析、扫描目录、索引、原子 JSON 写入、封存文件集合。 |
| `src/deep-*.ts`、`src/secure-read.ts`、`src/state-lock.ts` | Deep 编排、隔离源码读取和跨进程锁。 |
| `src/target.ts` | 目标解析、文件清单、内容哈希，以及语言与大小上限。 |
| `src/git.ts` | Git 版本、diff 与变更文件查询。 |
| `src/tools.ts` | 31 个 `codex_security_*` 工具定义及其参数 schema。 |
| `src/routes.ts` | 工作台使用的 `/plugins/codex-security` HTTP 路由。 |
| `src/contracts.ts` | 发现规范化与指纹、coverage、SARIF 以及策略门槛。 |
| `src/schema.ts` | 按 `schemas/` 对封存文档执行 AJV 校验。 |
| `src/types.ts` | 共享的扫描、发现、覆盖与记录类型。 |
| `src/util.ts` | 文件系统、哈希、时间戳与 JSON 辅助函数。 |
| `src/client/index.tsx` | 工作台设置区块及其 fetch 调用。 |
| `tests/*.test.mjs` | 单元、真实 host 集成与扫描回归测试。 |

</details>

-----

<a id="further-exploration"></a>
## 延伸阅读

- [CHANGELOG.md](CHANGELOG.md) — 发布历史与尚未发布的修复。
- [docs/TOOLS.md](docs/TOOLS.md) — 每个工具的参数、返回结构与生命周期规则。
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — host 生命周期、目标绑定、状态与封存、并发。
- [docs/ARTIFACTS.md](docs/ARTIFACTS.md) — 扫描、发现、覆盖与 manifest 的产物约定。
- [docs/SPEC.md](docs/SPEC.md) — 产品表面、配置、存储与工作台路由。
- [docs/VALIDATION.md](docs/VALIDATION.md) — 自动化检查与包检查命令。
- [schemas/](schemas/) — 封存时强制执行的 JSON Schema 约定。
- [references/](references/) — 扫描技能使用的安全指引。
- [examples/](examples/) — 一个已完成的扫描与一个旧版已完成的扫描。
- [DeepSeek Harness package-bundle 模板](https://github.com/deepseek-ai/deepseek-harness/blob/master/.agents/skills/dsh-doc-writing/templates/package-bundle.md) — 本 README 遵循的文档约定。
- [Apache-2.0 许可证](LICENSE)。

-----

<a id="model-experience"></a>
## 模型体验

间接地，通过注册的 31 个工具 schema 与16 个内置技能描述：它们的名称、描述与参数 schema 进入模型的工具与技能目录，而扫描状态只有在 agent 调用工具后以 JSON 结果的形式到达模型。

#### KV Cache 影响

启用这一层会向 host 为会话构建的 prompt 前缀中加入 31 个工具定义与16 个技能目录条目，移除时则删除同样的文本。会话期间目录保持稳定，因此新增的 token 属于缓存的 prefix，不会逐轮增长；开始、更新与完成扫描只是在 prefix 之后追加普通的工具结果与 assistant 消息。自动 worker 还会收到审查提示和其请求的已验证源码分块。

<a id="known-limitations-and-deferred-work"></a>
## 已知限制与后续工作

这些限制说明这一层在什么情况下不适用，以及它对周围 profile 的要求。

- **模型审查** — host 存储并校验 agent 提交的内容，无法证明模型理解了每个文件，也无法保证覆盖穷尽。
- **静态审查** — 受限 worker 不构建或执行目标代码；配置的模型服务可能使用网络，运行期弱点不在静态证据范围内。
- **Deep 预算** — 自动模式限制 worker、尝试次数、无新发现轮数与时间，但不设 token 或金额上限；手动模式的预算仅供参考。
- **本地状态** — 跨进程协调需要可信本地目录和可靠的 SQLite 文件锁；失败的中途封存可能留下中间文件。
- **封存是单向的** — agent 产物只能在扫描运行期间写入，`codex_security_save_artifact` 会拒绝封存文件与内部路径；triage 是完成后的唯一修改途径，且不会改动已封存文档。
- **默认限制导出范围** — 写入状态目录、进程工作目录与目标根路径之外需要 `allowExportOutsideWorkspace: true`；导出到 `repositories/` 下的扫描存储始终被拒绝。
- **文件导出需要原生支持** — 文件导出需要与平台匹配的可选二进制包；缺少时文件导出与自动 worker 源码读取会安全失败，手动扫描与内存导出仍可用。该二进制包没有依赖安装脚本。
- **清单上限决定证据范围** — `maxFiles` 与 `maxFileBytes` 限制可审查清单，不可读文件会变成警告，快照摘要只覆盖清单内的内容，因此超出上限的文件不在证据范围内。
- **比较不能证明修复** — `codex_security_compare_scans` 要求目标、模式与范围兼容、覆盖完整且清单未被截断的已完成扫描，并且只做指纹分类；指纹缺失不等于已验证修复。

<a id="dev-note"></a>
### 开发者注记

<details>
<summary>维护者工作上下文 — 点击展开</summary>

`npm run build` 先删除 `lib/`，用 `tsc -p tsconfig.json` 编译 host，用 `tsc -p tsconfig.client.json` 编译客户端，再运行 `node scripts/bundle-client.mjs` 把 `lib/client.js` 封装为 DSH 模块加载器格式。`npm test` 先构建，再运行 `node --test tests/*.test.mjs`；`npm run typecheck` 用 `--noEmit` 运行两个编译项目；`npm pack --dry-run` 列出发布文件。`engines` 要求 Node.js 22.19 或更新版本，host 需要 `@deepseek-ai/cordis`（~4.1.0）与 `@deepseek-ai/dsh-skill`（>=0.2.2-rc.2 <0.3.0）作为 peer 依赖，`devDependencies` 中固定为 DSH 0.2.2-rc.2 的包用于支撑 host 集成测试。编译后的 `lib/` 已纳入版本管理，CI 会检查重新构建后它保持不变，因此应修改 `src/` 后重新构建，而不是直接改 `lib/`。profile 的 `data/codex-security` 目录下的扫描状态属于用户数据：`index.json` 可重建，`scan-manifest.json` 封存每次完成的扫描，删除已封存文件会破坏 manifest 所描述的证据。

</details>
