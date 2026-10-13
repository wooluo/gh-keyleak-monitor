"""密钥有效性校验（可选功能）。

按密钥类型路由到各家**只读、无副作用**的 GET 端点：
- OpenAI        → GET /v1/models（不消耗模型额度）
- GitHub PAT    → GET /user
- Anthropic     → GET /v1/models
- Google        → GET /v1beta/models
- Telegram Bot  → GET /bot<token>/getMe

以下类型**不支持主动校验**，返回 'skip'：
- AWS        使用他人凭证调用 STS 会在对方 CloudTrail 留痕并触发告警；
- Stripe     任何端点都会拉取他人账户数据；
- Slack / SendGrid / OpenRouter / 私钥等无合适的无副作用探测端点。

仅建议在授权场景使用，例如监控自有组织的密钥泄漏后是否仍有效、
需要判断处置紧迫性的场景。每个指纹只请求一次，结果缓存在数据库中。
"""
import urllib.error
import urllib.request

UA = "gh-keyleak-monitor/1.1"


def _openai(key, timeout):
    return _get_bearer("https://api.openai.com/v1/models", key, timeout)


def _github(key, timeout):
    return _get_bearer("https://api.github.com/user", key, timeout)


def _anthropic(key, timeout):
    return _get_json("https://api.anthropic.com/v1/models", timeout, headers={
        "x-api-key": key, "anthropic-version": "2023-06-01"})


def _google(key, timeout):
    return _get_json(
        "https://generativelanguage.googleapis.com/v1beta/models", timeout,
        headers={"x-goog-api-key": key})


def _telegram(key, timeout):
    return _get_json(f"https://api.telegram.org/bot{key}/getMe", timeout)


# key_type 前缀 → 校验函数。不支持主动校验的类型不在此表内。
VERIFIERS = {
    "openai": _openai,
    "github": _github,
    "anthropic": _anthropic,
    "google": _google,
    "telegram": _telegram,
}


def _get_bearer(url, key, timeout) -> str:
    return _get_json(url, timeout, headers={"Authorization": f"Bearer {key}"})


def _get_json(url, timeout, headers=None) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "valid" if resp.status == 200 else f"http_{resp.status}"
    except urllib.error.HTTPError as e:
        e.read()
        if e.code == 401:
            return "invalid"  # 已吊销 / 无效
        if e.code == 403:
            return "invalid_or_forbidden"  # 被吊销或权限不足，至少"不再可用"
        if e.code == 429:
            return "unknown_429"
        return f"error_{e.code}"
    except Exception:
        return "error_network"


def verify_key(key: str, key_type: str = "", timeout: int = 15) -> str:
    """返回 'valid' / 'invalid' / 'skip' / 其他状态字符串。"""
    if not key_type:  # 旧调用方式：默认 OpenAI
        key_type = "openai"
    for prefix, fn in VERIFIERS.items():
        if key_type.startswith(prefix):
            return fn(key, timeout)
    return "skip"
