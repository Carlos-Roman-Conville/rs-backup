"""Tests for backup.py against a throwaway root and repo (python -m pytest test_backup.py, or python test_backup.py).
Everything lives in a temp folder; the deny ACEs it sets are lifted before the folder is removed."""
import datetime as dt
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup  # noqa: E402


def sh(*a, cwd=None):
    return subprocess.run(list(a), cwd=cwd, capture_output=True, text=True, check=True).stdout


def commit(repo: Path, name: str, text: str, msg: str):
    (repo / name).write_text(text, encoding="utf-8")
    sh("git", "add", name, cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", msg, cwd=repo)


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bkp-test-"))
        self.src = self.tmp / "live" / "repo"
        self.src.mkdir(parents=True)
        sh("git", "init", "-q", "-b", "main", cwd=self.src)
        commit(self.src, "a.txt", "one", "first")
        self.c = {"root": str(self.tmp / "backups"), "repos": {"repo": str(self.src)},
                  "snapshot_sources": {"live": str(self.tmp / "live")}, "exclude_dirs": ["node_modules"],
                  "retention": {"all_hours": 24, "hourly_days": 7, "daily_days": 60},
                  "restore_test": {"repo": "repo", "every_days": 7, "expect_tests": 0},
                  "restore_test_log": str(self.tmp / "rt.jsonl"), "gates": {}}

    def tearDown(self):
        backup.unprotect(self.tmp)
        for p in self.tmp.rglob("*"):
            try:
                os.chmod(p, 0o666)
            except OSError:
                pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_mirror_adds_history_never_removes(self):
        self.assertEqual(backup.mirror_one(self.c, "repo", str(self.src), init=False)[0], "skipped")
        state, msg = backup.mirror_one(self.c, "repo", str(self.src), init=True)
        self.assertEqual(state, "ok", msg)
        m = backup.mirror_dir(self.c, "repo")
        first = sh("git", "rev-parse", "HEAD", cwd=self.src).strip()
        # amend = non-fast-forward: kept under refs/rewritten, main keeps the original
        sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--amend", "-m", "amended", cwd=self.src)
        state, msg = backup.mirror_one(self.c, "repo", str(self.src), init=False)
        self.assertIn("rewritten kept", msg)
        self.assertEqual(sh("git", "rev-parse", "main", cwd=m).strip(), first)
        self.assertIn(sh("git", "rev-parse", "HEAD", cwd=self.src).strip(), sh("git", "for-each-ref", cwd=m))
        # second run with the same divergence keeps nothing new
        _, msg = backup.mirror_one(self.c, "repo", str(self.src), init=False)
        self.assertNotIn("rewritten kept", msg)
        # deleting a branch in the mirror is refused
        r = subprocess.run(["git", "push", m.as_posix(), ":refs/heads/main"], cwd=self.src, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        # ...and so is deleting or moving a tag (git's own deny settings cover refs/heads/* only; the hook covers the rest)
        amended = sh("git", "rev-parse", "HEAD", cwd=self.src).strip()
        sh("git", "tag", "v1", amended, cwd=self.src)
        backup.mirror_one(self.c, "repo", str(self.src), init=False)
        r = subprocess.run(["git", "push", m.as_posix(), ":refs/tags/v1"], cwd=self.src, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        sh("git", "tag", "-f", "v1", first, cwd=self.src)  # not a descendant of the mirrored tag
        r = subprocess.run(["git", "push", "-f", m.as_posix(), "refs/tags/v1"], cwd=self.src, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sh("git", "rev-parse", "refs/tags/v1", cwd=m).strip(), amended)
        # pushes still work after the mirror is delete-protected, and the objects cannot be deleted
        backup.protect_mirror(m)
        commit(self.src, "b.txt", "two", "second")
        self.assertEqual(backup.mirror_one(self.c, "repo", str(self.src), init=False)[0], "ok")
        obj = next(p for p in (m / "objects").rglob("*") if p.is_file() and len(p.parent.name) == 2)
        with self.assertRaises(PermissionError):
            obj.unlink()

    def test_snapshot_dedups_protects_and_skips_links(self):
        (self.src / "node_modules").mkdir()
        (self.src / "node_modules" / "x.js").write_text("x")
        (self.src / "dirty.txt").write_text("uncommitted")
        target = self.tmp / "outside"
        target.mkdir()
        (target / "precious.txt").write_text("keep me")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(self.src / "jn"), str(target)], capture_output=True, check=True)
        backup.mirror_one(self.c, "repo", str(self.src), init=True)
        a = backup.argparse.Namespace()
        self.assertEqual(backup.cmd_snapshot(a, self.c), 0)
        s1 = backup.snaps(self.c)[-1]
        self.assertTrue((s1 / "live" / "repo" / "dirty.txt").is_file())
        self.assertFalse((s1 / "live" / "repo" / "node_modules").exists())
        self.assertFalse((s1 / "live" / "repo" / "jn").exists())
        self.assertTrue((s1 / "git" / "repo.bundle").is_file())
        with self.assertRaises(PermissionError):
            (s1 / "live" / "repo" / "dirty.txt").unlink()
        with self.assertRaises(PermissionError):
            os.rename(s1, s1.with_name("2000-01-01-0000"))
        self.assertTrue((target / "precious.txt").is_file())

    def test_second_snapshot_hardlinks_and_prune_reprotects(self):
        a = backup.argparse.Namespace()
        backup.mirror_one(self.c, "repo", str(self.src), init=True)
        backup.cmd_snapshot(a, self.c)
        s1 = backup.snaps(self.c)[-1]
        # a second snapshot in another minute name
        backup.unprotect(s1)
        os.rename(s1, s1.with_name("2000-01-01-0000"))
        backup.protect(s1.with_name("2000-01-01-0000"))
        backup.cmd_snapshot(a, self.c)
        old, new = backup.snaps(self.c)
        self.assertEqual(os.stat(new / "live" / "repo" / "a.txt").st_ino, os.stat(old / "live" / "repo" / "a.txt").st_ino)
        self.assertEqual(os.stat(new / "git" / "repo.bundle").st_ino, os.stat(old / "git" / "repo.bundle").st_ino)
        backup.cmd_prune(backup.argparse.Namespace(dry=False), self.c)
        self.assertEqual([p.name for p in backup.snaps(self.c)], [new.name])
        with self.assertRaises(PermissionError):
            (new / "live" / "repo" / "a.txt").unlink()

    def test_keep_set(self):
        now = dt.datetime(2026, 10, 30, 12, 0)
        names = [(now - dt.timedelta(minutes=30 * i)).strftime(backup.STAMP) for i in range(0, 48 * 70)]
        keep = backup.keep_set(names, now, self.c["retention"])
        self.assertEqual(sum(1 for n in names if now - dt.datetime.strptime(n, backup.STAMP) <= dt.timedelta(hours=24)),
                         len([n for n in keep if now - dt.datetime.strptime(n, backup.STAMP) <= dt.timedelta(hours=24)]))
        self.assertLessEqual(len(keep), 49 + 24 * 6 + 54)
        self.assertNotIn(names[-1], keep)

    def test_restore_reapplies_uncommitted_and_later_snapshot_commits(self):
        a = backup.argparse.Namespace()
        backup.mirror_one(self.c, "repo", str(self.src), init=True)
        commit(self.src, "c.txt", "after mirror", "not mirrored yet")
        (self.src / "a.txt").write_text("edited, uncommitted")
        (self.src / "new.txt").write_text("untracked")
        backup.cmd_snapshot(a, self.c)
        rep = backup.restore(self.c, "repo", dest=self.tmp / "restored", gates=False)
        d = self.tmp / "restored"
        self.assertEqual(rep["commit"], sh("git", "rev-parse", "HEAD", cwd=self.src).strip())
        self.assertEqual((d / "c.txt").read_text(), "after mirror")
        self.assertEqual((d / "a.txt").read_text(), "edited, uncommitted")
        self.assertEqual((d / "new.txt").read_text(), "untracked")
        with self.assertRaises(SystemExit):
            backup.restore(self.c, "repo", dest=d, gates=False)

    def test_access_check_reports_what_this_account_can_do(self):
        backup.mirror_one(self.c, "repo", str(self.src), init=True)
        m = backup.mirror_dir(self.c, "repo")
        backup.ensure_canary_ref(m)
        backup.cmd_snapshot(backup.argparse.Namespace(), self.c)
        res = backup.access_check(self.c)
        got = {x["attempt"]: x["result"] for x in res["checks"]}
        self.assertEqual(got["append to a snapshot file"], "refused")
        self.assertEqual(got["delete a snapshot file"], "refused")
        self.assertEqual(got["rename a snapshot folder"], "refused")
        self.assertEqual(got[f"delete mirror ref {backup.CANARY_REF} by push"], "refused")
        # The owner account can still edit a ref file and lift a deny ACE: the check must say so, and put both back.
        self.assertEqual(got[f"delete mirror ref {backup.CANARY_REF} by editing the mirror"], "ALLOWED")
        self.assertEqual(got["remove the snapshot's deny ACE (owner's WRITE_DAC)"], "ALLOWED")
        self.assertFalse(res["pass"])
        self.assertEqual(subprocess.run(["git", "rev-parse", "-q", "--verify", backup.CANARY_REF], cwd=m).returncode, 0)
        with self.assertRaises(PermissionError):
            (backup.snaps(self.c)[-1] / backup.CANARY).unlink()

    def test_restore_from_protected_mirror_is_disposable(self):
        backup.mirror_one(self.c, "repo", str(self.src), init=True)
        backup.protect_mirror(backup.mirror_dir(self.c, "repo"))
        d = self.tmp / "restored"
        backup.restore(self.c, "repo", dest=d, gates=False)
        backup.rmtree(d)  # a hard-linked clone would share the mirror's deny-delete ACE and fail here
        self.assertFalse(d.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
