"""导出 CSV / JSON 报告。默认掩码密钥，--include-full 才输出完整值。"""
import csv
import io
import json

COLUMNS = ["first_seen", "key_type", "repo", "path", "line", "key",
           "verified", "seen_count", "url", "fingerprint", "source", "last_seen"]


def export(rows, fmt: str = "csv", out: str = None, include_full: bool = False) -> str:
    records = []
    for r in rows:
        d = dict(r)
        d["key"] = d["key_full"] if include_full else d["key_masked"]
        records.append({c: d.get(c, "") for c in COLUMNS})

    if fmt == "json":
        text = json.dumps(records, ensure_ascii=False, indent=2)
    else:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(records)
        text = buf.getvalue()

    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
    return text
