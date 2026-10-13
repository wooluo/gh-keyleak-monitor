"""GitHub API 客户端（仅标准库），处理一级/二级限流与常见错误。"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"
UA = "gh-keyleak-monitor/1.0"


class GitHubError(Exception):
    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code


class RateLimited(Exception):
    def __init__(self, wait_seconds):
        super().__init__(f"rate limited, wait {wait_seconds}s")
        self.wait_seconds = wait_seconds


class GitHubClient:
    def __init__(self, token: str, timeout: int = 20):
        if not token:
            raise GitHubError(
                "缺少 GitHub Token：代码搜索接口必须认证。"
                "请设置 GITHUB_TOKEN 环境变量、写入 .env，或先 gh auth login")
        self.token = token
        self.timeout = timeout

    def _request(self, url: str, params: dict = None):
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": UA,
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8")), dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if e.code in (403, 429):
                # 二级限流：带 Retry-After
                retry = e.headers.get("Retry-After")
                if retry:
                    raise RateLimited(min(int(retry), 600))
                # 一级限流：额度耗尽，按 Reset 时间等待
                remaining = e.headers.get("X-RateLimit-Remaining")
                reset = e.headers.get("X-RateLimit-Reset")
                if remaining == "0" and reset:
                    wait = max(int(reset) - int(time.time()), 1)
                    raise RateLimited(min(wait, 3700))
                raise GitHubError(f"GitHub 拒绝请求({e.code})：{body[:300]}", e.code)
            if e.code == 401:
                raise GitHubError("Token 无效或已过期(401)", e.code)
            raise GitHubError(f"HTTP {e.code}: {body[:300]}", e.code)
        except urllib.error.URLError as e:
            raise GitHubError(f"网络错误: {e.reason}")

    def search_code(self, query: str, page: int = 1, per_page: int = 100) -> dict:
        params = {"q": query, "per_page": per_page, "page": page,
                  "sort": "indexed", "order": "desc"}
        try:
            data, _ = self._request(f"{API_BASE}/search/code", params)
        except GitHubError as e:
            if e.code == 422:  # 某些端点不接受 sort 参数时降级重试
                params.pop("sort")
                params.pop("order")
                data, _ = self._request(f"{API_BASE}/search/code", params)
            else:
                raise
        return data

    def get_raw(self, repo_full: str, path: str, ref: str = "HEAD",
                max_bytes: int = 2_000_000):
        """拉取 raw 文件内容；过大/二进制/已删除返回 None。"""
        url = f"{RAW_BASE}/{repo_full}/{ref}/{urllib.parse.quote(path)}"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read(max_bytes + 1)
        except (urllib.error.HTTPError, urllib.error.URLError):
            return None
        if len(data) > max_bytes or b"\x00" in data[:1024]:
            return None
        return data.decode("utf-8", "replace")

    def rate_limit(self) -> dict:
        data, _ = self._request(f"{API_BASE}/rate_limit")
        return data
