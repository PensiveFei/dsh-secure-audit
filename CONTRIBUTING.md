# 贡献指南 / Contributing

感谢你帮助改进 `dsh-secure-audit`。问题报告、复现、测试、文档、翻译和代码
都会得到致谢。安全工具的审查还会关注误报、漏报、资源预算与证据脱敏。

## 环境准备

- 安装 Git、Node.js **20 或以上**与 npm，推荐 Node.js 24。
- CI 运行 Linux Node 20 / 22 / 24，以及 Windows Node 24；报告问题时请保留
  精确版本和测试中的跳过项，不要把跳过检查当作已验证。
- 克隆仓库（外部贡献者先 fork），创建独立分支；使用已提交的
  `package-lock.json`，不要在 DSH 的真实 profile 目录中安装开发依赖。

```bash
git clone https://github.com/PensiveFei/dsh-secure-audit.git
cd dsh-secure-audit
git switch -c fix/short-description
node --version
npm --version
npm ci
```

本项目没有构建步骤，源码就是 npm 产物。单元测试不要求启动完整 DSH 宿主。
宿主集成改动请另在隔离 profile 验证，并记录 DSH 与 `@deepseek-ai/dsh-tools`
版本、profile 类型及实际执行过的检查；参考
[验证矩阵](docs/verification-matrix.md)。不要把开发依赖安装进用户的现有 profile。

## 测试命令

从仓库根目录执行，与 CI 保持一致：

```bash
npm run lint       # JavaScript 语法与源码密钥扫描
npm test           # node --test
npm run eval       # 攻击样本与正常样本评估
npm pack --dry-run # 检查发布文件清单，不上传
```

调试时可用 `npm run test:watch`，或 `node --test tests/redact.test.js`
只运行相关测试。PR 填写每条命令、结果、平台和跳过项；未执行时说明原因。
lint 不会替你审查所有附件，请人工检查日志、截图和报告是否包含敏感数据。

## Adding or changing an injection rule

Rules live in `lib/rules.js`. Every rule **must** ship with test cases:

1. An adversarial case in `tests/fixtures/adversarial-samples.js` — the
   attack text and the expected decision.
2. If the rule risks false positives (almost all do), a benign case pinned to
   `allow` (see the existing entries: "build a bomb shelter", "jailbreak
   detection", "你现在是怎么想的", "运行命令 npm install").
3. Bump `RULESET_VERSION` in `lib/rules.js` so cached scan results invalidate.

Regex requirements: no nested quantifiers, bounded alternations. Catastrophic
backtracking is rejected in review (see `SECURITY.md`).

## Changing audit checks

Checks live in `lib/audit.js` and are registered in the `CHECKS` table.
Requirements:

- Read-only: `stat` / `readdir` / `readFile` / env / `os` only. No writes.
- Deterministic: fixed order, sorted arrays, no randomness.
- Redacted evidence: run evidence through `sanitize()`; never include raw
  secret values or user paths.
- A test asserting shape, status, and evidence redaction for the new check.

## Changing the logger or redaction

- New PII types go into `lib/rules.js` (`PII_RULES`) with a `mask` function
  and a test in `tests/redact.test.js`.
- Sensitive field names in the logger are a fixed set (`REDACT_FIELDS` in
  `lib/logger.js`); extending it is a deliberate, documented decision.

## Secrets hygiene

- No real credentials, ever. Test fixtures use `sk-TEST-…` /
  `not-a-real-…` markers that match the redaction rules but not secret
  scanners (CI runs the scan on every push).
- If you add a file that looks like a key, the CI secret scan will flag it;
  change the value to an obviously fake one.

## Pull request process

1. 先搜索已有 Issue/PR。较大的行为或依赖变更先说明问题、预期与范围；
   安全漏洞按 [SECURITY.md](SECURITY.md) 私密报告，不发公开复现或真实数据。
2. 在分支上修改，添加能复现行为的测试，保持 PR 聚焦。
3. 执行上述检查。依赖声明有变化时同步刷新锁文件，并验证 `npm ci`；
   不要重新引入安装时自动拉取另一套 DSH 核心包的必需 peer 依赖。
4. 行为变更在 `CHANGELOG.md` 新增未发布条目（Added / Fixed / Upgrade notes /
   Known issues）；纯文档修改可说明不适用。不要改写已发布版本的历史记录。
5. 向 `main` 发 PR，填写模板中的版本、系统、复现、日志、脱敏报告与署名偏好。
   无日志或无报告时明确写明原因，不要留空。所有 CI 检查通过后再合并。

### 提交规范

使用 `type(scope): 简短说明`，scope 可省略。常用类型：`fix`、`feat`、`docs`、
`test`、`refactor`、`chore`；例如 `fix(redact): preserve safe nested metadata`。
一项独立变更一个提交，不混入生成的 tarball、缓存、个人配置或凭据。
正文说明原因、验证方式并关联 Issue；只有确实解决问题时才用 `Closes #123`。
破坏性变更在正文写明迁移与回滚影响。贡献者无需自行升级版本或打 tag，
由维护者在发布时统一处理。若 squash 合并，维护者保留真实作者与已有
`Co-authored-by` 信息；不要编造身份或公开未经同意的邮箱。

## 问题报告与脱敏

使用 [Issue 表单](https://github.com/PensiveFei/dsh-secure-audit/issues/new/choose)。
除插件版本/commit 外，填写 DSH、Node.js、npm、操作系统版本和架构，
最小复现步骤、预期/实际结果及相关日志。

脱敏报告至少说明：检查过哪些日志/截图/附件，替换了哪些数据类别，
替换是否影响复现，以及检查的覆盖范围和限制。使用虚构样本，替换 API key、
Authorization/Cookie、个人信息、会话正文、用户名路径和私有地址；保留错误码、
规则 ID 与非敏感结构。审计报告只提供必要的脱敏摘要，注明未扫描、部分扫描、
被跳过与截断的部分。**脱敏工具输出也必须人工复核，不能保证完全脱敏。**
真实漏洞、泄露或可利用绕过仍走私密安全渠道。

## 及时致谢与明确归属（维护者）

- 以 **3 个工作日内首次回应**为目标，在 Issue/PR 首次有效回复中感谢贡献者，
  说明已受理、待补材料或下一步；无法及时处理时如实说明，不承诺固定修复日期。
  私密漏洞另遵循 SECURITY.md 的 72 小时确认目标，未经许可不公开报告者。
- 合并或关闭时说明结果并再次感谢，关联修复 PR；代码、报告、复现、测试、
  文档和评审分别注明贡献。采用 PR 中确认的公开署名；匿名请求写为“匿名贡献者”。
- 为每项进入发布的社区贡献记录 `@handle + 贡献内容 + Issue/PR 链接`，保留在
  Release 的 **贡献与致谢 / Credits** 一节。转述、移植或协作修复仍保留原始归属，
  不把维护者的整合工作写成全部原创。
- 自动生成的提交/PR 列表只作核对线索，可能遗漏报告者和测试者；逐项对照
  本次版本范围的 Issue/PR、CHANGELOG 和署名偏好补齐。不要杜撰贡献者。

## 发布流程（维护者）

1. 确认目标提交和 CI 全绿，执行 lint、test、eval、`npm pack --dry-run`。
   按 SemVer 决定版本；0.x 的不兼容改动也要说明迁移和回滚限制。
2. 同步 `package.json` 与 `package-lock.json` 的版本，整理 CHANGELOG 的四个
   分类，写明实际验证过的 DSH 快照和已知限制；提交并通过 CI。
3. 在该发布提交创建并推送 `vX.Y.Z` tag，确保 tag 与 package 版本一致。
   tag 不可变，已发布的回归用新版本修复。
4. `.github/workflows/release.yml` 会重新检查并打包，生成含 tarball 的 **draft**。
   保留草稿已有正文，按 [Release 模板](.github/RELEASE_TEMPLATE.md) 补齐说明，
   按上一节逐项核对署名、贡献类型及 Issue/PR 链接；无社区贡献时如实写明。
   不要用模板或自动生成内容覆盖已确认的 Notes/Credits。
   验证实际 Release 资产的 SHA-256，不能用另一份本地重打包产物的哈希替代。
5. 检查升级/回滚、已知限制、归属与资产后，将 draft 发布。带预发布号或含
   不兼容改动时核对 prerelease 标记。发布会触发 `publish.yml`，通过 npm
   Trusted Publishing（OIDC）发布（工作流使用 Node 24，要求 npm 11.5.1+）；
   不需要长期 npm token。
6. 若 Release 事件未触发或补发历史 tag，使用以下命令。`publish_ref` 必须
   指向已核验的 tag；`dry_run=true` 只演练，不能作为发布成功证据：

   ```bash
   gh workflow run publish.yml --repo PensiveFei/dsh-secure-audit --ref main -f publish_ref=refs/tags/vX.Y.Z
   ```

7. 检查发布日志中的实际上传和 provenance 签名，等待 registry 可见后核对
   `npm view dsh-secure-audit@X.Y.Z version dist`；下载 npm 与 GitHub tarball
   比较字节与哈希。若工作流提示版本已存在，仍须核对现有产物。
   用实际资产校验值更新两份 README 的完整性表；核对 Release 非意外 draft、
   npm 版本/渠道正确。最后回到相关 Issue/PR 说明可升级版本并致谢。

## Meta-security checklist for reviewers

- No write paths added to `lib/`.
- Error messages do not leak paths or stack traces.
- Logged fields are already-safe summary data or PII-masked.
- New dependencies: justify; the current surface is one peer dependency
  plus Node builtins.
