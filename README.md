# gh-keyleak-monitor — GitHub OpenAI API Key 泄漏监测工具

监测 GitHub 公开仓库中泄漏的 OpenAI API Key（`sk-proj-` / `sk-svcacct-` / `sk-admin-` / 经典 `sk-` 等 formats）。纯 Python 标准库实现，**无需安装任何依赖**（Python ≥ 3.9）。

## ⚠️ 合规声明（请先阅读）

本工具仅用于**授权的**安全监测场景：

- 监控**自有组织 / 自有仓库**的密钥泄漏（推荐配合 `--org` 使用）；
- 安全研究中的**负责任披露**（发现他人泄漏后，通过 GitHub 安全通告 / 仓库所有者 / `security@` 渠道反馈，**切勿使用他人密钥**）；
- 企业蓝队 / SOC 的外部泄漏面巡检。

使用者需遵守当地法律法规与 GitHub 服务条款。终端与报告**默认只显示掩码密钥**，完整密钥仅保存在本地数据库中供事件响应使用。

## 工作原理

```
GitHub Code Search API（按 indexed 倒序，聚焦新入库文件）
        │  命中文件列表
        ▼
raw.githubusercontent.com 拉取原始文件（≤2MB，跳过二进制）
        │
        ▼
正则识别 + 占位符黑名单 + 香农熵过滤（压误报）
        │
        ▼
sha256 指纹去重 → SQLite（findings.db）
        ├─ 可选：GET /v1/models 校验密钥是否仍有效（不消耗额度，每指纹一次）
        ├─ 可选：Webhook 通知（飞书/钉钉/企业微信自动适配）
        └─ 导出 CSV / JSON 报告（默认掩码）
```

## 快速开始

```bash
cd gh-keyleak-monitor

# 1. 配置 Token（三选一）
export GITHUB_TOKEN=ghp_xxx            # 方式一：环境变量
cp .env.example .env && vim .env       # 方式二：.env 文件
gh auth login                          # 方式三：复用 gh CLI 登录（自动发现）

# 2. 扫一轮（默认 3 组内置查询语句；深翻页信噪比更高）
python3 -m ghmonitor search --page-offset 5 --pages 3

# 只监控自己的组织（强烈推荐的生产用法）
python3 -m ghmonitor search --org your-company

# 3. 持续监控（每 10 分钟一轮，起始页自动轮换，Ctrl+C 退出）
python3 -m ghmonitor monitor --org your-company --interval 600

# 4. 导出报告
python3 -m ghmonitor report --format csv --out reports/findings.csv
python3 -m ghmonitor report --format json --limit 50
python3 -m ghmonitor report --include-full --out ir_full.csv   # 含完整密钥，供事件响应

# 5. 自查本地代码库
python3 -m ghmonitor scan-path ../myproject
```

> 注意：顶层参数 `--db` / `--token` 需放在子命令之前，如
> `python3 -m ghmonitor --db /tmp/a.db search`。

## 子命令与常用参数

| 命令 | 说明 | 常用参数 |
|---|---|---|
| `search` | 执行一轮搜索扫描 | `-q` 自定义语句（可重复）、`--preset default\|config`、`--org`/`--user` 范围、`--pages`、`--page-offset`、`--per-page`、`--verify`、`--webhook`、`--max-wait` |
| `monitor` | 持续轮询 | 同上 + `--interval`（默认 300s）、`--no-rotate` |
| `report` | 导出/查看发现 | `--format csv\|json`、`--out`、`--limit`、`--include-full` |
| `scan-path` | 扫描本地文件/目录 | 位置参数路径、`--verify` |

内置查询预设（`--preset`，可用 `-q` 覆盖）：

```
default:  "sk-proj-" language:Python        # 代码文件为主
          "OPENAI_API_KEY=sk-" language:Shell
          "sk-proj-" language:JavaScript

config:   "sk-proj-" language:JSON          # 配置文件聚焦（json / ini / env 形态），
          "OPENAI_API_KEY" language:INI     # 即网页端 path:*.json / *.properties / *.env
          "sk-proj-" language:INI           # 语法的 REST 可用近似
```

**REST 与网页端搜索语法支持矩阵（2026-10 实测）**——网页端那套 `path:` 组合语法**不能**直接搬进脚本/API：

| 语法 | 网页端 | REST API 实测 |
|---|---|---|
| `path:*.json` / `path:.env` / `path:*.log` | ✓ | ✗ 全部 0 命中 |
| `(path:*.xml OR path:*.json) "key"` 括号分组 | ✓ | ✗ HTTP 422 解析失败 |
| `-path:*.md` 排除文档 | ✓ | ✗ 静默无效 |
| `/"regex"/` 正则 | ✓ | ✗ 返回 0 |
| `language:Python/JSON/INI` | ✓ | ✓（替代 path: 做文件类型聚焦） |
| `org:xxx` | ✓ | ✓（`--org` 生产用法已验证） |

**查询策略（实测结论，2026-10）**：

- REST 搜索的头部结果（第 1~几页）几乎全是文档/教程占位符，`-path:*.md` 在 REST 中**不生效**，用 `language:` 限定代码文件才有效（非文档占比立刻从 ~0% 升到 100%）；
- 真实格式密钥集中在**深页**（实测第 7/12/30 页均捞到，第 1 页为 0）——单次排查建议 `--page-offset 5 --pages 5` 起步；
- `monitor` 模式默认每轮起始页自动 +1（1~40 循环）翻新区域，`--no-rotate` 关闭。

**生态现实**：GitHub 已对公开仓库默认开启 push protection，且 OpenAI 是 secret scanning 合作方——真实密钥 push 后通常很快被自动吊销并从搜索结果中过滤。因此本工具捞到的"真实格式"密钥多数**已被吊销**，其价值在于：泄漏事件的证据链（谁、何时、哪个仓库）、自有组织的泄漏面巡检、以及 GitHub 过滤不彻底的漏网/fork 场景。若需追"还活着的"密钥，重点应是自有组织监控（`--org`）+ `--verify` 判断处置紧迫性。

## 密钥有效性校验（--verify）

对每个新发现指纹请求一次 `GET https://api.openai.com/v1/models`（免费、不消耗模型额度）：`200 → valid`（密钥仍有效，需紧急处置），`401 → invalid`（已吊销/失效）。结果缓存在数据库。

> 仅对有权监测的密钥使用（如自有组织资产）。

## 数据与输出

- `findings.db`（SQLite）：字段含指纹、类型、仓库、路径、行号、URL、首/末次发现时间、命中次数、校验状态；`UNIQUE(fingerprint, repo, path, line)` 去重，重复命中只累加计数。
- 终端实时输出形如：

```
查询: "sk-proj-" language:Python
  第 5 页（抓 3 页）: 50 个文件（总命中 26112）
  ★ [openai_project] your-company/demo config/settings.py:12 sk-proj-9f3K...c7Qd
本轮完成: 新增 1 条 / 重复 0 条；累计 3 条，涉及 2 个不同密钥、2 个仓库
```

## 限流策略

- 代码搜索 API：认证后 30 次/分钟 → 分页间自动 sleep 2.5s；
- 二级限流（403 + `Retry-After`）与一级限流（`X-RateLimit-Reset`）自动等待重试（上限 `--max-wait`，连续 3 次后跳过该查询）；
- raw 文件拉取间隔 0.3s。

## 扩展规则

在 `ghmonitor/scanner.py` 的 `PATTERNS` 中追加正则即可，例如：

```python
("anthropic", re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b")),
("google_api", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
```

## 已知限制

- GitHub 代码搜索只索引**默认分支**且需要文件已被索引，历史提交、未合并分支、刚推送未入库的内容无法覆盖——全量历史排查请配合 `gitleaks` / `trufflehog` 扫描 clone 下来的仓库；
- 跨行拆分的密钥、截图/图片中的密钥无法识别；
- 高熵阈值（3.2）与占位符黑名单已过滤大部分文档示例，极端构造的假密钥仍可能误报。

## 目录结构

```
gh-keyleak-monitor/
├── ghmonitor/
│   ├── cli.py          # 命令行入口（search/monitor/report/scan-path）
│   ├── scanner.py      # 正则 + 熵 + 占位符过滤
│   ├── github.py       # GitHub API 客户端（限流处理）
│   ├── store.py        # SQLite 存储与去重
│   ├── verify.py       # 密钥有效性校验（可选）
│   ├── report.py       # CSV/JSON 导出
│   ├── notify.py       # Webhook 通知
│   └── config.py       # Token/配置解析
├── tests/test_scanner.py
├── .env.example
└── README.md
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```
