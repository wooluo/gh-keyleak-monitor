"""scanner / store / report 单元测试（全部使用合成的假密钥，不含真实凭据）。"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghmonitor.report import export
from ghmonitor.scanner import (Finding, is_placeholder, mask_key,
                               scan_text, shannon_entropy)
from ghmonitor.store import Store


class TestPresets(unittest.TestCase):
    def test_presets_structure(self):
        from ghmonitor.cli import DEFAULT_QUERIES, PRESETS
        self.assertIn("default", PRESETS)
        self.assertIn("config", PRESETS)
        self.assertEqual(DEFAULT_QUERIES, PRESETS["default"])
        for name, queries in PRESETS.items():
            self.assertTrue(queries, f"预设 {name} 不能为空")
            for q in queries:
                self.assertNotIn("path:", q, "path: 限定符在 REST 中无效，不应出现在预设里")
                self.assertNotIn("(", q, "括号分组在 REST 中 422，不应出现在预设里")


# 32 个不同字符循环拼接，保证高熵且格式正确（纯测试用途，非真实密钥）
_BLOCK = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
FAKE_PROJECT = "sk-proj-" + _BLOCK * 2
FAKE_LEGACY = "sk-" + _BLOCK + "6"      # 33 字符随机段
FAKE_SVCACCT = "sk-svcacct-" + _BLOCK * 2


class TestScanner(unittest.TestCase):
    def test_detect_project_key(self):
        text = f'OPENAI_API_KEY = "{FAKE_PROJECT}"\nprint("hi")\n'
        found = scan_text(text)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].key_type, "openai_project")
        self.assertEqual(found[0].key, FAKE_PROJECT)
        self.assertEqual(found[0].line, 1)

    def test_detect_legacy_key(self):
        found = scan_text(f"export OPENAI_API_KEY={FAKE_LEGACY}\n")
        self.assertEqual([f.key_type for f in found], ["openai_legacy"])

    def test_detect_svcacct_key(self):
        found = scan_text(f"key: {FAKE_SVCACCT}")
        self.assertEqual([f.key_type for f in found], ["openai_service_account"])

    def test_exclude_other_vendors(self):
        text = (f'ANTHROPIC = "sk-ant-api03-{_BLOCK * 2}"\n'
                f'OPENROUTER = "sk-or-v1-{_BLOCK * 2}"\n')
        self.assertEqual(scan_text(text), [])

    def test_exclude_placeholder_repeats(self):
        self.assertEqual(scan_text('K="sk-proj-' + "a" * 60 + '"'), [])
        self.assertEqual(scan_text('K="sk-' + "x" * 48 + '"'), [])

    def test_exclude_placeholder_words(self):
        self.assertEqual(scan_text('K="sk-proj-your-api-key-here-1234567890123456789012345678901234567890"'), [])
        self.assertEqual(scan_text('K="sk-proj-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"'), [])

    def test_line_numbers_multiline(self):
        text = f"# comment\nFOO=1\nBAR='{FAKE_PROJECT}'\n"
        found = scan_text(text)
        self.assertEqual(found[0].line, 3)

    def test_dedup_within_file(self):
        text = f"A={FAKE_PROJECT}\nB={FAKE_PROJECT}\n"
        self.assertEqual(len(scan_text(text)), 2)  # 不同行各记一条

    def test_entropy_and_helpers(self):
        self.assertGreater(shannon_entropy(_BLOCK), 4.5)
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertTrue(is_placeholder("sk-proj-" + "ab" * 30))
        self.assertFalse(is_placeholder(FAKE_PROJECT))
        masked = mask_key(FAKE_PROJECT)
        self.assertNotIn(_BLOCK, masked)
        self.assertTrue(masked.startswith("sk-proj-") and masked.endswith(FAKE_PROJECT[-4:]))


class TestStoreAndReport(unittest.TestCase):
    def setUp(self):
        fd, self.dbpath = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.dbpath)
        self.store = Store(self.dbpath)

    def tearDown(self):
        self.store.close()
        os.unlink(self.dbpath)

    def test_save_dedup_and_stats(self):
        common = dict(key=FAKE_PROJECT, key_type="openai_project",
                      repo="octocat/demo", path="config.py", url="http://x")
        self.assertEqual(self.store.save(line=1, **common), "new")
        self.assertEqual(self.store.save(line=1, **common), "seen")   # 同位置去重
        self.assertEqual(self.store.save(line=5, **common), "new")    # 同库不同行
        self.assertEqual(self.store.save(key=FAKE_PROJECT, key_type="openai_project",
                                         repo="other/repo", path="a.py", line=1,
                                         url="http://y"), "new")       # 跨仓库新发现
        st = self.store.stats()
        self.assertEqual(st["n"], 3)
        self.assertEqual(st["keys"], 1)
        self.assertEqual(st["repos"], 2)

    def test_verify_marking(self):
        self.store.save(key=FAKE_LEGACY, key_type="openai_legacy",
                        repo="a/b", path="c", line=1, url="u")
        fps = self.store.unverified_fingerprints()
        self.assertEqual(len(fps), 1)
        self.store.mark_verified(fps[0][0], "invalid")
        self.assertEqual(self.store.unverified_fingerprints(), [])

    def test_report_masked_by_default(self):
        self.store.save(key=FAKE_PROJECT, key_type="openai_project",
                        repo="a/b", path="c.py", line=1, url="u")
        csv_text = export(self.store.all(), "csv")
        self.assertNotIn(FAKE_PROJECT, csv_text)
        self.assertIn("a/b", csv_text)
        full_text = export(self.store.all(), "csv", include_full=True)
        self.assertIn(FAKE_PROJECT, full_text)


if __name__ == "__main__":
    unittest.main()
