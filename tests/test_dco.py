"""Exercise real Git histories, including unsigned ancestors and bot trailers."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


CHECKER = Path(__file__).resolve().parents[1] / "scripts" / "check-dco.py"
AUTHOR = "Fixture Author <author@example.test>"


class DCOTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cwd = self.tmp.name
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture Author")
        self.git("config", "user.email", "author@example.test")
        self.commit("Historical unsigned commit")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.cwd, env=self.env,
                              text=True, capture_output=True, check=True).stdout

    def commit(self, message, author=AUTHOR):
        self.git("commit", "-q", "--allow-empty", "--author", author, "-m", message)

    def result(self, base=None, head="HEAD"):
        return subprocess.run(["python3", "-I", str(CHECKER), base or self.base, head],
                              cwd=self.cwd, env=self.env, text=True, capture_output=True)

    def test_signed_contribution_ignores_unsigned_history(self):
        self.commit("Change\n\nSigned-off-by: " + AUTHOR)
        self.assertEqual(self.result().returncode, 0)

    def test_every_commit_is_checked(self):
        self.commit("Unsigned change")
        self.commit("Signed change\n\nSigned-off-by: " + AUTHOR)
        self.assertEqual(self.result().returncode, 1)

    def test_wrong_name_or_email_is_rejected(self):
        for signoff in ["Other <author@example.test>", "Fixture Author <other@example.test>"]:
            with self.subTest(signoff=signoff):
                self.commit("Change\n\nSigned-off-by: " + signoff)
                self.assertEqual(self.result(base="HEAD^").returncode, 1)

    def test_signoff_in_prose_is_not_a_trailer(self):
        self.commit("Change\n\nSigned-off-by: " + AUTHOR + "\n\nThis is prose after the example.")
        self.assertEqual(self.result().returncode, 1)

    def test_signoff_after_divider_is_a_valid_trailer(self):
        self.git("commit", "-q", "--allow-empty", "--signoff", "-m",
                 "Change\n\n---\nAdditional explanation.")
        self.assertEqual(self.result().returncode, 0)

    def test_signoff_before_divider_and_prose_is_not_a_trailer(self):
        self.commit("Change\n\nSigned-off-by: " + AUTHOR + "\n\n---\nAdditional explanation.")
        self.assertEqual(self.result().returncode, 1)

    def test_repository_module_cannot_shadow_standard_library(self):
        self.commit("Unsigned change")
        scripts = Path(self.cwd) / "scripts"
        scripts.mkdir()
        checker = scripts / "check-dco.py"
        checker.write_bytes(CHECKER.read_bytes())
        (scripts / "subprocess.py").write_text("raise SystemExit(0)\n")
        result = subprocess.run(["python3", "-I", str(checker), self.base, "HEAD"],
                                cwd=self.cwd, env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)

    def test_multiple_signoffs_preserve_the_author(self):
        self.commit("Change\n\nSigned-off-by: " + AUTHOR + "\nSigned-off-by: Other <other@example.test>")
        self.assertEqual(self.result().returncode, 0)

    def test_native_dependabot_signoff(self):
        self.commit("Dependency update\n\nSigned-off-by: dependabot[bot] <support@github.com>",
                    "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>")
        self.assertEqual(self.result().returncode, 0)

    def test_bots_are_not_exempt(self):
        self.commit("Unsigned bot update",
                    "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>")
        self.assertEqual(self.result().returncode, 1)

    def test_bot_alias_does_not_cover_human_authors(self):
        self.commit("Change\n\nSigned-off-by: dependabot[bot] <support@github.com>")
        self.assertEqual(self.result().returncode, 1)

    def test_invalid_or_empty_ranges_fail_closed(self):
        self.assertEqual(self.result().returncode, 2)
        self.assertEqual(self.result(base="missing-ref").returncode, 2)
        self.assertEqual(self.result(head="--all").returncode, 2)

    def test_shallow_history_is_rejected(self):
        self.commit("Change\n\nSigned-off-by: " + AUTHOR)
        clone = tempfile.TemporaryDirectory()
        self.addCleanup(clone.cleanup)
        self.git("clone", "-q", "--no-local", "--depth", "2", self.cwd, clone.name)
        self.cwd = clone.name
        self.git("cat-file", "-e", self.base + "^{commit}")
        self.assertEqual(self.result().returncode, 2)

    def test_indented_squash_history_is_not_a_final_signoff(self):
        self.commit("Change A\n\nSigned-off-by: " + AUTHOR)
        self.commit("Change B\n\nSigned-off-by: " + AUTHOR)
        self.git("checkout", "-q", "-b", "squashed", self.base)
        self.git("merge", "--squash", "main")
        self.git("commit", "-q", "--allow-empty", "-F", ".git/SQUASH_MSG")
        self.assertEqual(self.result().returncode, 1)

    def test_explicitly_signed_squash_preserves_source_messages(self):
        self.commit("Change A\n\nSigned-off-by: " + AUTHOR)
        self.commit("Change B\n\nSigned-off-by: " + AUTHOR)
        self.git("checkout", "-q", "-b", "squashed", self.base)
        self.git("merge", "--squash", "main")
        self.git("commit", "-q", "--allow-empty", "--signoff", "-F", ".git/SQUASH_MSG")
        self.assertEqual(self.result().returncode, 0)
        message = self.git("show", "-s", "--format=%B", "HEAD")
        self.assertIn("Change A", message)
        self.assertIn("Change B", message)

    def test_unsigned_merge_commit_is_rejected(self):
        self.git("checkout", "-q", "-b", "feature")
        self.commit("Change\n\nSigned-off-by: " + AUTHOR)
        self.git("checkout", "-q", "main")
        self.git("merge", "--no-ff", "feature", "-m", "Unsigned branch merge")
        self.assertEqual(self.result().returncode, 1)


if __name__ == "__main__":
    unittest.main()
