"""命令行入口：search / monitor / report / scan-path。"""
import argparse
import sys
import time
from pathlib import Path

from . import __version__
from . import config as cfgmod
from .github import GitHubClient, GitHubError, RateLimited
from .report import export
from .scanner import mask_key, scan_text
from .store import Store

# 查询预设。注意网页端语法与 REST 接口差异极大（2026-10 实测，见 README 支持矩阵）：
# path:*.json / path:.env 在 REST 全部 0 命中、括号 OR 分组直接 422、-path:*.md 静默无效，
# 网页端的 path: 组合语法不能用于 REST；改用 language: 限定文件类型，实测有效。
PRESETS = {
    # 代码文件为主（默认）：真实密钥集中在深页，配合 --page-offset 5+ 使用
    "default": [
        '"sk-proj-" language:Python',
        '"OPENAI_API_KEY=sk-" language:Shell',
        '"sk-proj-" language:JavaScript',
    ],
    # 配置文件聚焦：用 language:JSON/INI 近似网页端 path:*.json / *.properties / *.env
    "config": [
        '"sk-proj-" language:JSON',
        '"OPENAI_API_KEY" language:INI',
        '"sk-proj-" language:INI',
    ],
}
DEFAULT_QUERIES = PRESETS["default"]

SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
             ".tgz", ".tar", ".jar", ".woff", ".woff2", ".ttf", ".otf",
             ".mp3", ".mp4", ".mov", ".db", ".sqlite3"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             ".idea", ".vscode", "dist", "build"}


def _add_search_args(p, with_interval=False):
    p.add_argument("-q", "--query", action="append", default=None,
                   help="自定义 GitHub 搜索语句，可重复指定；默认使用内置语句")
    p.add_argument("--preset", choices=sorted(PRESETS), default="default",
                   help="查询预设: default=代码文件(Python/Shell/JS), "
                        "config=配置文件(JSON/INI, 即网页端 path:*.json 等语法的 REST 近似)")
    p.add_argument("--org", default=None, help="限定组织（推荐：监控自有组织，REST 实测有效）")
    p.add_argument("--user", default=None, help="限定用户")
    p.add_argument("--pages", type=int, default=2, help="每个查询抓取的页数（默认 2）")
    p.add_argument("--page-offset", type=int, default=1,
                   help="起始页码（默认 1；深翻页信噪比更高）")
    p.add_argument("--per-page", type=int, default=50, help="每页条数（默认 50，最大 100）")
    p.add_argument("--max-wait", type=int, default=600, help="单次限流最长等待秒数")
    p.add_argument("--verify", action="store_true",
                   help="校验发现密钥的有效性（仅限授权场景使用）")
    p.add_argument("--webhook", default=None, help="发现新增泄漏时推送 Webhook")
    if with_interval:
        p.add_argument("--interval", type=int, default=300,
                       help="轮询间隔秒数（默认 300）")
        p.add_argument("--no-rotate", action="store_true",
                       help="不自动轮换每轮的起始页码（默认每轮 +1，1~40 循环）")


def build_parser():
    p = argparse.ArgumentParser(
        prog="ghmonitor",
        description="GitHub OpenAI API Key 泄漏监测工具"
                    "（仅用于授权安全监测、自有资产监控与负责任披露）")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--db", default=None, help="SQLite 数据库路径（默认 ./findings.db）")
    p.add_argument("--token", default=None,
                   help="GitHub Token（默认依次取 --token / GITHUB_TOKEN / .env / gh auth token）")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("search", help="执行一轮搜索扫描")
    _add_search_args(sp)
    sp.set_defaults(func=cmd_search)

    mp = sub.add_parser("monitor", help="持续轮询监控（Ctrl+C 退出）")
    _add_search_args(mp, with_interval=True)
    mp.set_defaults(func=cmd_monitor)

    rp = sub.add_parser("report", help="导出/查看数据库中的发现")
    rp.add_argument("--format", choices=["csv", "json"], default="csv")
    rp.add_argument("--out", default=None, help="输出文件路径（默认打印到终端）")
    rp.add_argument("--limit", type=int, default=0, help="只输出最近 N 条")
    rp.add_argument("--include-full", action="store_true",
                    help="报告中包含完整密钥（默认掩码）")
    rp.set_defaults(func=cmd_report)

    lp = sub.add_parser("scan-path", help="扫描本地文件/目录（自查代码库）")
    lp.add_argument("paths", nargs="+", help="要扫描的文件或目录")
    lp.add_argument("--verify", action="store_true",
                    help="校验发现密钥的有效性（仅限授权场景使用）")
    lp.set_defaults(func=cmd_scan_path)
    return p


def _process_remote_item(client, store, item, new_lines) -> tuple:
    repo = item["repository"]["full_name"]
    path = item["path"]
    base_url = item.get("html_url") or f"https://github.com/{repo}/blob/HEAD/{path}"
    text = client.get_raw(repo, path)
    if not text:
        return 0, 0
    new = seen = 0
    for f in scan_text(text):
        status = store.save(key=f.key, key_type=f.key_type, repo=repo, path=path,
                            line=f.line, url=f"{base_url}#L{f.line}", source="github")
        if status == "new":
            new += 1
            line = f"[{f.key_type}] {repo} {path}:{f.line} {mask_key(f.key)}"
            print("  ★ " + line)
            new_lines.append(line)
        else:
            seen += 1
    return new, seen


def _run_verify(store):
    from .verify import verify_key
    fps = store.unverified_fingerprints()
    if not fps:
        print("没有待校验的密钥")
        return
    print(f"校验 {len(fps)} 个密钥有效性（GET /v1/models，不消耗额度）...")
    for fp, key in fps:
        status = verify_key(key)
        store.mark_verified(fp, status)
        print(f"  {fp} → {status}")
        time.sleep(0.5)


def _run_search_once(cfg, args) -> int:
    store = Store(cfg.db_path)
    client = GitHubClient(cfg.token)
    queries = list(args.query or PRESETS[args.preset])
    scope = f" org:{args.org}" if args.org else (f" user:{args.user}" if args.user else "")
    queries = [q + scope for q in queries]

    new_lines = []
    total_new = total_seen = 0
    first_page = getattr(args, "page_offset", 1)
    for q in queries:
        print(f"查询: {q}")
        page, retries = first_page, 0
        while page < first_page + args.pages:
            try:
                data = client.search_code(q, page=page, per_page=args.per_page)
                retries = 0
            except RateLimited as e:
                retries += 1
                if retries > 3:
                    print("  连续触发限流，跳过该查询")
                    break
                wait = max(1, min(e.wait_seconds, args.max_wait))
                print(f"  触发限流，等待 {wait}s 后重试 ...")
                time.sleep(wait)
                continue
            items = data.get("items", [])
            print(f"  第 {page} 页（抓 {args.pages} 页）: {len(items)} 个文件"
                  f"（总命中 {data.get('total_count', '?')}）")
            for item in items:
                n, s = _process_remote_item(client, store, item, new_lines)
                total_new += n
                total_seen += s
                time.sleep(0.3)  # raw 请求礼貌间隔
            if len(items) < args.per_page:
                break
            page += 1
            time.sleep(2.5)  # 搜索接口认证后 30 次/分钟

    st = store.stats()
    print(f"\n本轮完成: 新增 {total_new} 条 / 重复 {total_seen} 条；"
          f"累计 {st['n']} 条，涉及 {st['keys']} 个不同密钥、{st['repos']} 个仓库")

    if args.verify and total_new:
        print("注意: 校验功能仅对有权监测的密钥使用（如自有组织资产）")
        _run_verify(store)

    webhook = args.webhook or cfg.webhook_url
    if webhook and new_lines:
        from .notify import send_webhook
        text = "GitHub 密钥泄漏监测：新增 %d 条\n%s" % (
            len(new_lines), "\n".join(new_lines[:20]))
        print("Webhook 推送" + ("成功" if send_webhook(webhook, text) else "失败"))

    store.close()
    return 0


def cmd_search(cfg, args) -> int:
    return _run_search_once(cfg, args)


def cmd_monitor(cfg, args) -> int:
    print(f"监控模式：每 {args.interval}s 一轮，数据库 {cfg.db_path}，Ctrl+C 退出")
    cycle = 0
    while True:
        cycle += 1
        if not args.no_rotate:
            # 每轮起始页 +1（1~40 循环），穿透 best-match 头部的文档区
            args.page_offset = (cycle - 1) % 40 + 1
        print(f"\n===== 第 {cycle} 轮 {time.strftime('%Y-%m-%d %H:%M:%S')}"
              f"（起始页 {args.page_offset}）=====")
        try:
            _run_search_once(cfg, args)
        except RateLimited as e:
            wait = max(1, min(e.wait_seconds, args.max_wait))
            print(f"触发限流，等待 {wait}s")
            time.sleep(wait)
        except GitHubError as e:
            print(f"GitHub 错误: {e}，{args.interval}s 后重试")
        time.sleep(args.interval)


def cmd_report(cfg, args) -> int:
    store = Store(cfg.db_path)
    rows = store.all()
    if args.limit:
        rows = rows[:args.limit]
    if not rows:
        print("数据库为空")
        store.close()
        return 0
    export(rows, args.format, args.out, args.include_full)
    if args.out:
        print(f"已导出 {len(rows)} 条 → {args.out}")
    else:
        print(export(rows, args.format, None, args.include_full))
    store.close()
    return 0


def cmd_scan_path(cfg, args) -> int:
    store = Store(cfg.db_path)
    total_new = 0
    new_lines = []
    for p in args.paths:
        root = Path(p).expanduser()
        if root.is_file():
            files = [root]
        else:
            files = [f for f in root.rglob("*") if f.is_file()
                     and not (SKIP_DIRS & set(f.parts))
                     and f.suffix.lower() not in SKIP_EXTS]
        for fp in files:
            try:
                if fp.stat().st_size > 2_000_000:
                    continue
                data = fp.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:1024]:
                continue
            text = data.decode("utf-8", "replace")
            for f in scan_text(text):
                status = store.save(key=f.key, key_type=f.key_type, repo=str(root),
                                    path=str(fp), line=f.line, url=str(fp),
                                    source="local")
                if status == "new":
                    total_new += 1
                    line = f"[{f.key_type}] {fp}:{f.line} {mask_key(f.key)}"
                    print("  ★ " + line)
                    new_lines.append(line)
    st = store.stats()
    print(f"\n本地扫描完成: 新增 {total_new} 条；累计 {st['n']} 条")
    if args.verify and new_lines:
        print("注意: 校验功能仅对有权监测的密钥使用（如自有资产）")
        _run_verify(store)
    store.close()
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = cfgmod.Config()
    if args.db:
        cfg.db_path = args.db
    cfg.token = cfgmod.resolve_token(getattr(args, "token", None))
    cfg.webhook_url = cfgmod.resolve_webhook()
    try:
        return args.func(cfg, args) or 0
    except KeyboardInterrupt:
        print("\n已停止")
        return 130
    except GitHubError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
