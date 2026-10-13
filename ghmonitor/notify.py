"""通用 Webhook 通知：按 URL 自动适配飞书/钉钉/企业微信文本消息格式。"""
import json
import urllib.request


def send_webhook(url: str, text: str, timeout: int = 10) -> bool:
    u = url.lower()
    if "open.feishu.cn" in u or "larksuite" in u:
        payload = {"msg_type": "text", "content": {"text": text}}
    elif "dingtalk" in u:
        payload = {"msgtype": "text", "text": {"content": text}}
    elif "qyapi.weixin.qq.com" in u:
        payload = {"msgtype": "text", "text": {"content": text}}
    else:
        payload = {"text": text}

    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "User-Agent": "gh-keyleak-monitor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False
