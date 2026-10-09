"""Exercise release guards and fan-in without network or publishing effects."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(sys.argv.pop(1))
SHA = "a" * 40


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "Cargo.toml").write_text('[package]\nversion = "3.0.1"\n')
        for name in ("bin", "secrets", "inputs/archive/artifacts/release-archive", "inputs/container/artifacts/layout", "inputs/container/artifacts/provenance"):
            (self.root / name).mkdir(parents=True)
        self.archive = "ngit-grasp-3.0.1-x86_64-unknown-linux-musl.tar.gz"
        (self.root / "inputs/archive/artifacts/release-archive" / self.archive).write_bytes(b"predecessor archive")
        (self.root / "inputs/container/artifacts/layout/index.json").write_text("predecessor layout")
        (self.root / "secrets/NGIT_PUBLISHER_NBUNKSEC").write_text("private-nbunksec")
        (self.root / "secrets/CARGO_REGISTRY_TOKEN").write_text("private-cargo-token")
        self.mock("git", '''case "$1" in
fetch) exit 0;;
rev-parse) if [ "$2" = HEAD ]; then echo "$NGIT_CI_COMMIT_SHA"; else echo "${TEST_TAG_SHA:-$NGIT_CI_COMMIT_SHA}"; fi;;
for-each-ref) echo 12345;;
show) cat Cargo.toml;;
esac''')
        self.mock("ngit", 'printf "%s\\n" "$@" > "$HOME/publish-args"')
        self.mock("cargo", 'test "$CARGO_REGISTRY_TOKEN" = private-cargo-token\nprintf "%s\\n" "$@" > "$HOME/publish-args"')
        self.env = dict(os.environ, PATH=str(self.root / "bin") + ":" + os.environ["PATH"],
                        HOME=str(self.root), NGIT_CI_WORKFLOW_PATH=".ngit/nix/workflows/container_backfill.yaml", NGIT_CI_TRIGGER="push", NGIT_CI_REF_TYPE="tag",
                        NGIT_CI_REF="refs/tags/v3.0.1", NGIT_CI_COMMIT_SHA=SHA,
                        NGIT_CI_INPUTS=str(self.root / "inputs"), NGIT_CI_SECRETS_DIR=str(self.root / "secrets"))

    def mock(self, name, body):
        path = self.root / "bin" / name
        path.write_text("#!" + shutil.which("bash") + "\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def run_script(self, script):
        result = subprocess.run(["bash", "-euo", "pipefail", "-c",
                                 (SCRIPTS / "release-context.sh").read_text() + "\n" + (SCRIPTS / script).read_text()],
                                cwd=self.root, env=self.env, capture_output=True, text=True)
        self.assertNotIn("private-", result.stdout + result.stderr)
        return result

    def test_release_consumes_archive_and_passes_commit(self):
        result = self.run_script("publish-release.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "dist" / self.archive).read_bytes(), b"predecessor archive")
        args = (self.root / "publish-args").read_text()
        self.assertIn("--commit\n" + SHA, args)
        self.assertIn("--channel\nmain", args)
        self.assertNotIn("private-", args)

    def test_container_consumes_layout_on_manual_backfill(self):
        self.env["NGIT_CI_TRIGGER"] = "manual"
        historical = "b" * 40
        self.env["TEST_TAG_SHA"] = historical
        (self.root / "inputs/container/artifacts/provenance/provenance.json").write_text(json.dumps({
            "tag": "refs/tags/v3.0.1", "version": "3.0.1", "source_commit": historical, "workflow_commit": SHA}))
        result = self.run_script("publish-container.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "artifacts/ngit-grasp/index.json").read_text(), "predecessor layout")

    def test_container_rejects_changed_backfill_provenance(self):
        self.env["NGIT_CI_TRIGGER"] = "manual"
        (self.root / "inputs/container/artifacts/provenance/provenance.json").write_text(json.dumps({
            "tag": "refs/tags/v3.0.1", "version": "3.0.1", "source_commit": "b" * 40,
            "workflow_commit": SHA}))
        self.assertNotEqual(self.run_script("publish-container.sh").returncode, 0)
        self.assertFalse((self.root / "publish-args").exists())

    def test_crate_receives_secret_only_in_environment(self):
        result = self.run_script("publish-crates.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = (self.root / "publish-args").read_text()
        self.assertIn("--package\nngit-grasp", args)
        self.assertNotIn("private-", args)

    def test_guards_reject_before_publication(self):
        for key, value in (("NGIT_CI_REF", "refs/tags/v9.9.9"), ("NGIT_CI_REF_TYPE", "branch"),
                           ("NGIT_CI_TRIGGER", "pull_request"), ("TEST_TAG_SHA", "b" * 40)):
            with self.subTest(key=key):
                old = self.env.get(key)
                self.env[key] = value
                self.assertNotEqual(self.run_script("publish-release.sh").returncode, 0)
                self.assertFalse((self.root / "publish-args").exists())
                if old is None:
                    del self.env[key]
                else:
                    self.env[key] = old

    def test_manual_cannot_publish_crates_or_release(self):
        self.env["NGIT_CI_TRIGGER"] = "manual"
        for script in ("publish-crates.sh", "publish-release.sh"):
            self.assertNotEqual(self.run_script(script).returncode, 0)
        self.assertFalse((self.root / "publish-args").exists())

    def test_missing_predecessor_stops_publication(self):
        (self.root / "inputs/archive/artifacts/release-archive" / self.archive).unlink()
        self.assertNotEqual(self.run_script("publish-release.sh").returncode, 0)
        self.assertFalse((self.root / "publish-args").exists())


unittest.main()
