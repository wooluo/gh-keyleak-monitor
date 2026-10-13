"""密钥模式匹配与误报过滤：正则 + 占位符黑名单 + 香农熵。

覆盖主流硬编码密钥类型（OpenAI / Anthropic / OpenRouter / GitHub PAT /
AWS / Google / Stripe / Slack / Telegram / SendGrid / 私钥文件头等），
规则参考 gitleaks 常用规则精选，全部适配"逐行扫描"场景。
"""
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import NamedTuple


class Rule(NamedTuple):
    name: str
    pattern: re.Pattern
    # 熵值计算的取段方式:
    #   tail2        去掉前两段前缀（sk-proj-xxx → xxx），适合前缀式密钥
    #   whole        整串
    #   after_colon  最后一个冒号之后（Telegram bot token）
    #   none         不做熵检查（结构性匹配，如私钥文件头）
    entropy_part: str = "tail2"
    group: int = 0  # 密钥所在的捕获组（默认 0 = 整个匹配）


RULES = [
    # --- OpenAI ---
    ("openai_project", r"\bsk-proj-[A-Za-z0-9_-]{40,}\b"),
    ("openai_service_account", r"\bsk-svcacct-[A-Za-z0-9_-]{40,}\b"),
    ("openai_admin", r"\bsk-admin-[A-Za-z0-9_-]{40,}\b"),
    ("openai_session", r"\bsk-None-[A-Za-z0-9_-]{20,}\b"),
    # 经典格式 sk-xxx；负向前瞻排除其他厂商前缀（Anthropic / OpenRouter 等，它们有独立规则）
    ("openai_legacy", r"\bsk-(?!proj-|svcacct-|admin-|None-|ant-|or-v1-)[A-Za-z0-9_-]{32,}\b"),

    # --- 其他 LLM 厂商 ---
    ("anthropic", r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b"),
    ("openrouter", r"\bsk-or-v1-[A-Za-z0-9]{48,}\b"),

    # --- GitHub ---
    ("github_token", r"\bgh[posur]_[A-Za-z0-9]{36,255}\b"),
    ("github_fine_grained", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),

    # --- 云平台 ---
    ("aws_access_key", r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
     "whole"),
    # AWS Secret Key 无前缀，必须靠赋值上下文限定，40 位 base64ish 段在捕获组 1
    ("aws_secret", r"(?i)(?:aws[^.\n]{0,30}?(?:secret|sk)[^.\n]{0,30}?[\"'=:\s])"
                   r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", "whole", 1),
    ("google_api", r"\bAIza[0-9A-Za-z_\-]{35}\b", "whole"),

    # --- SaaS ---
    ("stripe_secret", r"\b[sr]k_live_[0-9a-zA-Z_-]{20,}\b", "whole"),
    ("slack_token", r"\bxox[abeoprs]-[0-9A-Za-z-]{10,}\b", "whole"),
    ("slack_webhook",
     r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}"
     r"/[A-Za-z0-9_]{20,}\b", "whole"),
    ("telegram_bot", r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b", "after_colon"),
    ("sendgrid", r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b", "whole"),

    # --- 私钥文件头（结构性命中，直接当泄漏处理）---
    ("private_key", r"-----BEGIN [A-Z0-9 ]{0,30}PRIVATE KEY(?: BLOCK)?-----",
     "none"),
]

# 元组形式书写便于追加注释；此处编译为 Rule 对象列表
RULES = [Rule(name, re.compile(pat), *(rest or ("tail2",)))
         for name, pat, *rest in RULES]

# 向后兼容旧字段名（README"扩展规则"曾引用）
PATTERNS = RULES

# 文档示例类占位符特征。真密钥的随机段是 base 系编码，出现这些英文词
# 的概率约为零，可以放心整串匹配（token/secret/your 等常见于教程示例）
_PLACEHOLDER = re.compile(
    r"(?i)(xxxx|your|example|changeme|placeholder|sample|dummy|fake|"
    r"token|secret|<[^>]*>|\$\{|\{\{)"
)

# 低于该熵值的命中按示例/占位符处理（真实密钥的随机段熵值通常 > 4）
ENTROPY_THRESHOLD = 3.2


@dataclass
class Finding:
    key: str
    key_type: str
    line: int
    line_text: str


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def entropy_segment(key: str, mode: str) -> str:
    if mode == "tail2":
        return key.split("-", 2)[-1]  # 去掉 sk- / sk-proj- 等前缀后的随机段
    if mode == "after_colon":
        return key.split(":")[-1]     # Telegram: 123456789:AAxxx
    return key  # whole / none


def is_placeholder(key: str, entropy_mode: str = "tail2") -> bool:
    if _PLACEHOLDER.search(key):
        return True
    if entropy_mode == "none":
        return False
    seg = entropy_segment(key, entropy_mode)
    if len(set(seg)) <= 3:  # sk-aaaaaaaa... 之类
        return True
    return shannon_entropy(seg) < ENTROPY_THRESHOLD


def mask_key(key: str) -> str:
    if len(key) <= 16:
        return key[:6] + "****"
    return f"{key[:12]}...{key[-4:]}"


def scan_text(text: str) -> list:
    """逐行扫描，返回去重后的 Finding 列表。"""
    results, seen = [], set()
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule in RULES:
            for m in rule.pattern.finditer(line):
                key = m.group(rule.group)
                if is_placeholder(key, rule.entropy_part):
                    continue
                k = (rule.name, key, lineno)
                if k in seen:
                    continue
                seen.add(k)
                results.append(Finding(key, rule.name, lineno, line.strip()[:200]))
    return results
