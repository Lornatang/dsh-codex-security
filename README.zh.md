# dsh-codex-security

面向 DeepSeek Harness（DSH）的 Agent 原生安全审查工作台，扫描模型移植自
[OpenAI codex-security](https://github.com/openai/codex-security)：由 Agent 对仓库执行
**静态安全审查**，把证据与覆盖范围记录为**封存的扫描产物**，并产出带稳定 ID、可跟踪
处置状态、可导出为 SARIF/JSON/CSV/Markdown 的发现。

需要 **DeepSeek Harness >= 0.2.2-rc.2** 与 **Node.js >= 22.19**。

> 这是一个独立的社区项目，与 OpenAI、DeepSeek 均无隶属或背书关系。产物契约、技能流程与
> 扫描/报告模型改编自 Apache License 2.0 许可的 OpenAI codex-security，详见 [NOTICE](NOTICE)。

## 项目定位

DSH 插件可以同时提供宿主工具、技能、HTTP 路由与客户端界面。本插件把这四者组合起来，
让一次安全审查变成结构化、可审计的产物集：

- Agent 绑定目标（仓库、指定路径、工作区或 diff），清点可审查的文本文件并创建扫描记录。
- 内置技能（`$security-scan`、`$security-diff-scan`、`$deep-security-scan` 等）
  指导 Agent 把源码当作不可信数据来审查、验证候选问题并记录覆盖范围。
- Agent 通过宿主工具记录候选问题、验证结论、攻击路径与草稿。
- 调用完成工具时，扫描被**封存**：`findings.json`、`coverage.json`、
  `scan-manifest.json` 与 `report.md` 写入 profile 状态目录，清单中记录各产物的 sha256。
- 发现项在多次扫描之间保持稳定指纹，因此可以验证修复、发现回归。

插件不会上传任何内容：只处理本地文件，也不会构建、执行或测试被审查的仓库。

## 功能特性

- **封存式扫描** —— 每个完成的扫描都会产出发现/覆盖/清单契约与人读报告；只有
  `completed` 状态的扫描会被封存，失败与取消的扫描保留记录但不产生封存产物。
- **三种扫描模式** —— `standard`（单轮证据驱动审查）、`prompt-only`（只做接单与报告骨架，
  不带编排语义）、`deep`（多轮扫描，并在扫描记录中保存 worker/发现预算）。
- **27 个宿主工具** —— `codex_security_*` 工具覆盖环境、目标、生命周期、证据、
  发现与处置、审查项、导出与扫描对比。
- **10 个技能** —— 插件加载时从 `skills/` 注册的 Agent 工作流。
- **深扫编排** —— worker 数量、发现轮次预算、连续无新增即停止以及时间上限；候选问题、
  验证与攻击路径在多轮之间持久化。
- **Diff 审查** —— 绑定提交区间、分支或工作区，并为每个变更文件记录一条审查项
  （`prepare_review_items` / `list_review_items`）。
- **修复验证** —— `compare_scans` 按指纹把发现划分为已关闭、仍存在或新增。
- **导出** —— SARIF 2.1.0、JSON、CSV 与 Markdown，默认写入状态目录；
  `failOnSeverity` 会在完成与导出时记录策略门禁结果。
- **Web 工作台** —— 设置中的 **Codex Security**（中文界面为“代码安全”）分区支持扫描列表、
  带严重级别标记与处置状态的发现表格、覆盖范围摘要与导出链接。
- **状态仅存本地** —— 扫描保存在 profile 数据目录下，可像其他 profile 数据一样删除。

## 安装

把包安装到你使用的 DSH profile：

```bash
dsh plugin --profile <profile> add dsh-codex-security
```

把 `<profile>` 替换为你的 profile 名称（例如 `desktop` 或 `web`），然后重启 DSH。
如果从终端启动 Web 界面，可用 `dsh web --no-open` 重启。

当该包在 DSH 插件市场（[dshmarket](https://dshmarket.com)）上架后，也可以直接在 DSH Web
界面的 **Plugins → Plugin Market** 中安装，无需命令行。上面的 CLI 命令始终可用。

卸载：

```bash
dsh plugin --profile <profile> remove dsh-codex-security
```

## 快速开始

1. 安装插件并重启 DSH（见上文）。
2. 在 DSH 中打开要审查的仓库。
3. 对 Agent 说：

   ```text
   Run a security scan of this repository.
   ```

   或者直接调用技能：

   ```text
   $security-scan
   ```

4. Agent 会检查环境（`codex_security_inspect_setup`）、绑定目标
   （`codex_security_inspect_target`）、创建扫描并审查源码；结束时记录草稿并通过
   `codex_security_complete_scan` 封存扫描。
5. 在 **Settings → Codex Security** 查看结果，或让 Agent 列出扫描、发现与覆盖范围。
   使用 `codex_security_export_findings` 导出。

常用变体：

```text
$security-diff-scan        # 审查 PR、提交区间、分支或工作区改动
$deep-security-scan        # 带发现预算的多轮穷尽式扫描
```

Agent 也可能主动提出审查，例如“帮我审查未提交改动中的安全回归”。

## 与 codex-security 的区别

| | OpenAI codex-security | dsh-codex-security |
| --- | --- | --- |
| 运行环境 | Codex 应用 / CLI / MCP | DeepSeek Harness 插件（宿主工具、技能、HTTP 路由、Web UI） |
| Agent 接口 | codex-security 命令与技能 | 27 个 `codex_security_*` 工具 + 10 个 DSH 技能 |
| 编排方式 | Codex Agent 工作流 | DSH Agent 工作流；深扫的 worker 与发现预算记录在扫描中 |
| 产物 | 上游扫描产物契约 | 相同的发现/覆盖/清单契约，适配的 ID（`cs_*`、`csf_*`、`occ_*`）与 DSH 专属指纹规则 |
| 云服务 | 无需云服务 | 无云服务、无遥测、不上传 |
| 代码执行 | 静态审查 | 仅静态审查：从不构建、执行或测试目标 |
| 自动修复 | Agent 辅助修复 | 插件从不自动打补丁；修复技能指导 Agent 修改，`compare_scans` 负责验证结果 |

## 工具速览

所有工具都返回 JSON 对象并以格式化 JSON 文本展示。完整参考见
[docs/TOOLS.md](docs/TOOLS.md)。

| 分组 | 工具 | 数量 |
| --- | --- | --- |
| 环境与目标 | `inspect_setup`、`inspect_target` | 2 |
| 扫描生命周期 | `start_standard_scan`、`start_prompt_only_scan`、`start_deep_scan`、`get_scan_context`、`update_scan_context`、`update_scan_progress`、`complete_scan`、`fail_scan`、`cancel_scan` | 9 |
| 证据与草稿 | `record_scan_draft`、`record_discovery_candidates`、`list_candidates`、`record_candidate_validations`、`record_candidate_attack_paths`、`save_artifact`、`read_artifact` | 7 |
| 发现与审查 | `list_scans`、`get_scan`、`list_findings`、`set_finding_triage`、`set_finding_remediation`、`prepare_review_items`、`list_review_items` | 7 |
| 导出与验证 | `export_findings`、`compare_scans` | 2 |

工具名统一带 `codex_security_` 前缀（例如 `codex_security_start_standard_scan`）。

## 技能

| 技能 | 用途 |
| --- | --- |
| `security-scan` | 对整仓或指定路径做安全审查，并封存为扫描 |
| `security-diff-scan` | 审查 PR、提交、分支或工作区 diff |
| `deep-security-scan` | 带发现 worker 与预算的多轮穷尽式扫描 |
| `fix-finding` | 把已验证的发现转成最小化、可验证的代码修改 |
| `verify-fix` | 重新扫描并与基线对比以证明修复有效 |
| `triage-finding` | 记录发现的处置状态与备注 |
| `threat-model` | 创建或更新仓库威胁模型 |
| `track-findings` | 跨扫描跟踪发现（已关闭/仍存在/新增） |
| `resolve-dependency-alert` | 调查并修复依赖告警 |
| `vulnerability-writeup` | 撰写可用于披露的漏洞报告 |

技能在运行时从 `skills/<name>/SKILL.md` 注册。

## 配置

在 DSH profile 的补丁文件
（`$DSH_HOME/profiles/<profile>/cordis.patch.yml`，默认 home 为 `~/.dsh`）中，
于 `codex-security` 插件行下配置：

```yaml
- id: codex-security
  name: 'dsh-codex-security'
  config:
    defaultMode: standard
    failOnSeverity: high
```

| 配置项 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `stateDir` | 字符串（绝对路径） | `""` | 覆盖扫描状态目录；为空表示 `<profile 数据目录>/codex-security`。 |
| `maxFiles` | 整数，1–200000 | `5000` | 单次扫描的清点上限。 |
| `maxFileBytes` | 整数，1024–67108864 | `1048576` | 单个文件读取的最大字节数。 |
| `defaultMode` | `standard` \| `prompt-only` \| `deep` | `standard` | 启动工具未指定 `mode` 时使用的模式。 |
| `failOnSeverity` | `informational` \| `low` \| `medium` \| `high` \| `critical` \| `off` | `high` | 完成与导出时报告的策略门禁阈值。 |
| `allowExportOutsideWorkspace` | 布尔 | `false` | 允许导出到工作目录与状态目录之外。 |
| `maxScanAgeDays` | 整数，1–3650 | `30` | 工作台使用的保留期提示。 |
| `deepWorkers` | 整数，1–32 | `4` | 深扫默认 worker 数量。 |
| `deepMaxDiscoveryRuns` | 整数，1–10000 | `40` | 深扫默认发现轮次预算。 |

## 扫描产物

完成的扫描会把产物保存在
`<stateDir>/repositories/<repoKey>/scans/<scanId>/`：

```text
scan.json              # 内部记录（生命周期、目标、清点、进度）
findings.json          # 封存的发现契约
coverage.json          # 封存的覆盖契约
scan-manifest.json     # 封存清单，含各产物 sha256
report.md              # 人读报告
threat-model.md        # 可选
candidates.json        # 深扫候选问题
validations.json       # 候选验证
attack-paths.json      # 候选攻击路径
triage.json            # 发现处置/修复状态
review-items.json      # diff 审查项
checkpoints/scan-draft.json
findings/<slug>/<slug>.md   # Agent 保存的漏洞报告（相对扫描目录）
artifacts/                  # Agent 保存的覆盖回执与证据
```

字段、ID 与指纹规则、覆盖处置、清单哈希、报告章节与 SARIF 映射见
[docs/ARTIFACTS.md](docs/ARTIFACTS.md)。JSON 示例见 [examples/](examples)。

## 安全模型

- **目标只读。** 插件只列举、读取文件并执行只读 git 命令，从不写入被审查仓库。
- **仅静态审查。** 不构建、不执行、不测试目标，也不发起网络请求；发现是基于源码的主张，
  而非运行时证明。
- **默认警惕提示词注入。** 仓库内容是“不可信数据”。技能要求 Agent 把源码、注释、文档与
  生成文件都当作数据而非指令，封存报告也会记录没有遵循目标中出现的任何指令。
- **密钥脱敏。** 技能要求把凭据与个人数据脱敏为短前缀加长度（例如
  `AKIA…[redacted, 40 chars]`），只引用路径与行号；插件也从不会连接服务去验证发现的凭据。
- **状态仅存本地。** 扫描、发现与导出都留在本地文件系统；导出到工作/状态目录之外需要
  显式开启 `allowExportOutsideWorkspace`。
- **仅显式导出。** 除工具调用显式要求的导出外，插件写入的内容都在配置的状态目录内。

## 文档

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) —— 包结构、模块、生命周期与状态。
- [docs/TOOLS.md](docs/TOOLS.md) —— 27 个工具的参数、返回值、错误与示例。
- [docs/ARTIFACTS.md](docs/ARTIFACTS.md) —— 发现/覆盖/清单/草稿契约。
- [docs/VALIDATION.md](docs/VALIDATION.md) —— 验收检查与插件自身的安全检查清单。
- [docs/SPEC.md](docs/SPEC.md) —— 权威实现规范。
- [skills/](skills) —— Agent 工作流；[references/](references) —— 上游参考材料。

## 环境要求

- 支持插件的 DeepSeek Harness >= 0.2.2-rc.2。
- Node.js >= 22.19。
- Git 可选。Git 仓库可获得提交、分支、远端与 diff 扫描；其他目录按目录快照审查。

## 常见问题

- **工作台没有扫描。** 先完成一次扫描再刷新；可用 `codex_security_inspect_setup` 查看
  实际生效的 `stateDir`。
- **Diff 扫描退化为目录快照。** Diff 扫描需要 git 仓库且基线提交可解析。
- **导出被拒绝。** 选择工作目录或状态目录内的路径，或开启
  `allowExportOutsideWorkspace`。
- **插件未加载。** 确认安装的 profile 与实际运行的 profile 一致，并在安装后重启 DSH。

## 许可证

Apache-2.0。参见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。NOTICE 记录了本项目对
OpenAI codex-security（Apache-2.0）的改编；DSH 宿主插件、工具、存储、路由与客户端工作台
是针对这些契约的独立重实现。
