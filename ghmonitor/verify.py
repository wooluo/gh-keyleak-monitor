"""密钥有效性校验（可选功能）。

仅建议在授权场景使用，例如监控自有组织的密钥泄漏后是否仍有效、
需要判断处置紧迫性的场景。GET /v1/models 不消耗模型额度，
每个指纹只请求一次，结果缓存在数据库中。
"""
import urllib.error
import urllib.request

_MODELS_URL = "https://api.openai.com/v1/models"


def verify_key(key: str, timeout: int = 15) -> str:
    """返回 'valid' / 'invalid' / 其他状态字符串。"""
    req = urllib.request.Request(_MODELS_URL, headers={
        "Authorization": f"Bearer {key}",
        "User-Agent": "gh-keyleak-monitor/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "valid" if resp.status == 200 else f"http_{resp.status}"
    except urllib.error.HTTPError as e:
        e.read()
        if e.code == 401:
            return "invalid"  # 已吊销 / 无效
        if e.code == 429:
            return "unknown_429"
        return f"error_{e.code}"
    except Exception:
        return "error_network"
