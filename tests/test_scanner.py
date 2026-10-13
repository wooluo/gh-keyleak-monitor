"""scanner / store / report 单元测试（全部使用合成的假密钥，不含真实凭据）。"""
import os
import sys
import tempfile
import unittest
import unittest.mock
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
        # Anthropic / OpenRouter 现为正式类型，且不应被 openai_legacy 重复命中
        text = (f'ANTHROPIC = "sk-ant-api03-{_BLOCK * 3}"\n'
                f'OPENROUTER = "sk-or-v1-{_BLOCK * 2}"\n')
        self.assertEqual([f.key_type for f in scan_text(text)],
                         ["anthropic", "openrouter"])

    def test_exclude_placeholder_repeats(self):
        self.assertEqual(scan_text('K="sk-proj-' + "a" * 60 + '"'), [])
        self.assertEqual(scan_text('K="sk-' + "x" * 48 + '"'), [])

    def test_exclude_placeholder_words(self):
        self.assertEqual(scan_text('K="sk-proj-your-api-key-here-1234567890123456789012345678901234567890"'), [])
        self.assertEqual(scan_text('K="sk-proj-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"'), [])
        # AWS 官方文档示例密钥（含 EXAMPLE，被黑名单拦截）
        self.assertEqual(scan_text('aws_access_key_id = AKIAIOSFODNN7EXAMPLE'), [])
        self.assertEqual(
            scan_text('aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), [])

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


# 各厂商合成假密钥（高熵随机段 + 正确格式，纯测试用途，非真实凭据）
FAKE_ANTHROPIC = "sk-ant-api03-" + _BLOCK * 3           # 96 字符随机段
FAKE_OPENROUTER = "sk-or-v1-" + _BLOCK * 2
FAKE_GITHUB = "ghp_" + _BLOCK + "AbCd"                   # 36 位
FAKE_GITHUB_FG = "github_pat_11AbCdEfGhIjKlMn_" + _BLOCK + "1234567890123456789"
FAKE_AWS_AKID = "AKIA" + "0123456789ABCDEF"              # 16 位全唯一字符
FAKE_AWS_SECRET = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/+=a"  # 40 位高熵
FAKE_GOOGLE = "AIza" + _BLOCK + "AbC"                # AIza + 35 位随机段
FAKE_STRIPE = "sk_live_" + _BLOCK + "AbCdEfGh"           # 36 位
# 段内混入字母：避免被 GitHub push protection 当作真实 Slack token 拦截
# （本仓库的测试数据就因此被拦过一次，见 README"生态现实"）
FAKE_SLACK = "xoxb-1234AbCdEf56-5678AbCdEf90-AbCdEfGhIjKlMnOpQrSt"
FAKE_SLACK_HOOK = ("https://hooks.slack.com/services/T0123ABCD4/B0123ABCD4/"
                   "AbCdEfGhIjKlMnOpQrStUvWxYz012345")
FAKE_TELEGRAM = "123456789:AA" + _BLOCK + "A"            # AA + 33 位随机段
FAKE_SENDGRID = "SG." + _BLOCK[:22] + "." + _BLOCK + "AbCdEfGhIjK"  # 22.43
FAKE_PRIVKEY = "-----BEGIN OPENSSH PRIVATE KEY-----"


class TestVendorKeys(unittest.TestCase):
    """16 类密钥的正则识别 + 熵/占位符过滤联动。"""

    def _one(self, key_type, text):
        found = scan_text(text)
        self.assertEqual([f.key_type for f in found], [key_type], text)
        return found[0]

    def test_llm_vendors(self):
        self._one("anthropic", f"ANTHROPIC_API_KEY='{FAKE_ANTHROPIC}'")
        self._one("openrouter", f"key: {FAKE_OPENROUTER}")

    def test_github_tokens(self):
        self._one("github_token", f"GITHUB_TOKEN={FAKE_GITHUB}")
        self._one("github_fine_grained", f'token = "{FAKE_GITHUB_FG}"')

    def test_aws(self):
        f = self._one("aws_access_key", f"aws_access_key_id = {FAKE_AWS_AKID}")
        self.assertEqual(f.key, FAKE_AWS_AKID)
        # Secret Key 依赖赋值上下文，密钥在捕获组 1
        f2 = self._one("aws_secret",
                       f'aws_secret_access_key = "{FAKE_AWS_SECRET}"')
        self.assertEqual(f2.key, FAKE_AWS_SECRET)

    def test_google_stripe_sendgrid(self):
        self._one("google_api", f'key = "{FAKE_GOOGLE}"')
        self._one("stripe_secret", f"STRIPE={FAKE_STRIPE}")
        self._one("sendgrid", f"SENDGRID_KEY = {FAKE_SENDGRID}")

    def test_slack_and_telegram(self):
        self._one("slack_token", f"SLACK={FAKE_SLACK}")
        self._one("slack_webhook", f"url = '{FAKE_SLACK_HOOK}'")
        self._one("telegram_bot", f"BOT_TOKEN={FAKE_TELEGRAM}")

    def test_private_key_header(self):
        # 私钥文件头无熵检查，结构性命中
        self._one("private_key", FAKE_PRIVKEY)
        self.assertEqual(scan_text("-----BEGIN CERTIFICATE-----"), [])

    def test_mixed_file(self):
        text = (f"A={FAKE_GITHUB}\nB={FAKE_AWS_AKID}\n"
                f"C={FAKE_GOOGLE}\nD={FAKE_TELEGRAM}\n")
        self.assertEqual([f.key_type for f in scan_text(text)],
                         ["github_token", "aws_access_key",
                          "google_api", "telegram_bot"])

    def test_vendor_placeholders(self):
        # 教程占位符：黑名单词 / 低熵，全部拦截
        for text in ('K="xoxb-your-token-here-AbCdEfGhIjKlMnOpQrStUvWxYz0123456"',
                     'K="xoxb-' + "a" * 40 + '"',
                     'K="ghp_' + "a" * 36 + '"',
                     "bot_token = 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"):
            self.assertEqual(scan_text(text), [], text)


class TestVerifyRouting(unittest.TestCase):
    """verify 按类型路由（skip 判断不发网络请求）。"""

    def test_supported_types_routed(self):
        from ghmonitor.verify import VERIFIERS
        for key_type in ("openai_project", "openai_legacy", "openai_session",
                         "github_token", "github_fine_grained",
                         "anthropic", "google_api", "telegram_bot"):
            self.assertTrue(any(key_type.startswith(p) for p in VERIFIERS),
                            f"{key_type} 应有校验端点")

    def test_unsupported_types_skip(self):
        from ghmonitor.verify import verify_key
        for key_type in ("aws_access_key", "aws_secret", "stripe_secret",
                         "slack_token", "slack_webhook", "sendgrid",
                         "private_key", "openrouter"):
            self.assertEqual(verify_key("fake", key_type, timeout=1), "skip")

    def test_default_type_is_openai(self):
        # 旧调用方式（不传 key_type）默认 OpenAI 端点
        from ghmonitor.verify import verify_key
        with unittest.mock.patch("ghmonitor.verify._get_json") as g:
            g.return_value = "invalid"
            self.assertEqual(verify_key("sk-x"), "invalid")
            g.assert_called_once()


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
