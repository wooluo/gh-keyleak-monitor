"""密钥模式匹配与误报过滤：正则 + 占位符黑名单 + 香农熵。"""
import math
import re
from collections import Counter
from dataclasses import dataclass

# OpenAI 各类密钥格式（新增格式在此追加即可，如其他厂商前缀）
PATTERNS = [
    ("openai_project", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{40,}\b")),
    ("openai_service_account", re.compile(r"\bsk-svcacct-[A-Za-z0-9_-]{40,}\b")),
    ("openai_admin", re.compile(r"\bsk-admin-[A-Za-z0-9_-]{40,}\b")),
    ("openai_session", re.compile(r"\bsk-None-[A-Za-z0-9_-]{20,}\b")),
    # 经典格式 sk-xxx；负向前瞻排除其他厂商前缀（Anthropic / OpenRouter 等）
    ("openai_legacy", re.compile(
        r"\bsk-(?!proj-|svcacct-|admin-|None-|ant-|or-v1-)[A-Za-z0-9_-]{32,}\b")),
]

# 文档示例类占位符特征
_PLACEHOLDER = re.compile(
    r"(?i)(xxxx|your[_-]?api[_-]?key|your[_-]?key|example|changeme|"
    r"placeholder|<[^>]*>|\$\{|\{\{)"
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


def is_placeholder(key: str) -> bool:
    if _PLACEHOLDER.search(key):
        return True
    tail = key.split("-", 2)[-1]  # 去掉 sk- / sk-proj- 等前缀后的随机段
    if len(set(tail)) <= 3:  # sk-aaaaaaaa... 之类
        return True
    if shannon_entropy(tail) < ENTROPY_THRESHOLD:
        return True
    return False


def mask_key(key: str) -> str:
    if len(key) <= 16:
        return key[:6] + "****"
    return f"{key[:12]}...{key[-4:]}"


def scan_text(text: str) -> list:
    """逐行扫描，返回去重后的 Finding 列表。"""
    results, seen = [], set()
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS:
            for m in pattern.finditer(line):
                key = m.group(0)
                if is_placeholder(key):
                    continue
                k = (name, key, lineno)
                if k in seen:
                    continue
                seen.add(k)
                results.append(Finding(key, name, lineno, line.strip()[:200]))
    return results
