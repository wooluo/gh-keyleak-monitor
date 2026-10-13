"""配置与凭据解析（Token 优先级: --token > 环境变量 > .env > gh auth token）。"""
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    token: str = ""
    db_path: str = str(PROJECT_ROOT / "findings.db")
    webhook_url: str = ""


def load_env_file(path: Path = None) -> dict:
    path = path or PROJECT_ROOT / ".env"
    result = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def resolve_token(explicit: str = None) -> str:
    if explicit:
        return explicit
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    env = load_env_file()
    if env.get("GITHUB_TOKEN"):
        return env["GITHUB_TOKEN"]
    # 本机已 gh auth login 的话直接复用
    try:
        r = subprocess.run(["gh", "auth", "token"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def resolve_webhook(explicit: str = None) -> str:
    if explicit:
        return explicit
    if os.environ.get("WEBHOOK_URL"):
        return os.environ["WEBHOOK_URL"]
    return load_env_file().get("WEBHOOK_URL", "")
