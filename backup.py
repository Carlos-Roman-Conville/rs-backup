"""Backup and recovery for the reality-sim platform (Rex, 2026-10-30, after I-1048). Spec: HQ/handoffs/controller/BACKUP.md.

    python backup.py mirror --path <repo>     # push one repo to its existing mirror (the belt hook; never creates one)
    python backup.py mirror --all --init      # every repo, creating missing mirrors (scheduled task / setup only)
    python backup.py snapshot                 # dated, hard-link-deduplicated, delete-protected filesystem snapshot
    python backup.py prune [--dry]            # retention: all for 24 h, hourly for 7 days, daily for 60 days
    python backup.py run                      # the 30-minute job: mirror --all --init, snapshot, prune, weekly restore test
    python backup.py status                   # JSON: mirrors, snapshots, restore test (the dashboard reads this)
    python backup.py restore <repo> [--snapshot NAME] [--dest DIR] [--no-gates]
    python backup.py restore-test             # restore the kernel into a disposable folder, run its gates, compare hashes
    python backup.py access-check             # as this account: tamper with a snapshot and a mirror ref; all must be refused

Only the scheduled task (running the protected copy in <root>/bin) and the mirror push write under the backup root;
an agent's belt unit reaches it only through `mirror --path`, which adds history and cannot remove any (the mirrors
refuse deletions and non-fast-forward updates). Nothing here follows a junction or symlink (I-1048).
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = HERE / "config.json"
REPARSE = 0x400          # FILE_ATTRIBUTE_REPARSE_POINT: junctions and symlinks, never followed
EVERYONE = "*S-1-1-0"
STAMP = "%Y-%m-%d-%H%M"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def cfg() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def root(c: dict) -> Path:
    return Path(c["root"])


def run(cmd: list[str], cwd: str | Path | None = None, env: dict | None = None, timeout: int = 1800) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, creationflags=NO_WINDOW)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s: {' '.join(cmd)}"


def git(*args: str, cwd: str | Path | None = None, env: dict | None = None) -> tuple[int, str]:
    return run(["git", *args], cwd=cwd, env=env)


def git_out(*args: str, cwd: str | Path | None = None, env: dict | None = None) -> tuple[int, bytes]:
    """stdout only, as bytes: for output that is data (a patch, a NUL list), never mixed with git's warnings."""
    p = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, creationflags=NO_WINDOW)
    return p.returncode, p.stdout


def norm(p: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(p))).rstrip("\\/")


# ---------------------------------------------------------------- repos and mirrors

def platform_repos(c: dict) -> dict[str, str]:
    """config.json `repos`, plus every git repo directly under a `platform_dirs` folder (a new keeper's repo is
    mirrored from the next run on, without a config edit)."""
    out = dict(c["repos"])
    known = {norm(p) for p in out.values()}
    for d in c.get("platform_dirs", []):
        for p in sorted(Path(d).iterdir()) if Path(d).is_dir() else []:
            if p.is_dir() and (p / ".git").exists() and norm(p) not in known and p.name not in out:
                out[p.name] = str(p)
                known.add(norm(p))
    return out


def repos(c: dict) -> dict[str, str]:
    """name -> path: the platform repos, then every belt repo in repos.txt that is a git repo."""
    out = platform_repos(c)
    f = Path(c.get("belt_repos_file", ""))
    if f.is_file():
        base = f.parent.parent  # repos.txt paths are relative to games/ (Games/Card Games)
        known = {norm(p) for p in out.values()}
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = (base / line).resolve()
            if norm(p) in known or not (p / ".git").exists():
                continue
            name = p.name if line != "." else "games"
            if name in out:
                name = f"{name}-{abs(hash(norm(p))) % 10000}"
            out[name] = str(p)
            known.add(norm(p))
    return out


def mirror_dir(c: dict, name: str) -> Path:
    return root(c) / "git" / f"{name}.git"


MIRROR_CONFIG = (("receive.denyDeletes", "true"), ("receive.denyNonFastForwards", "true"),
                 ("receive.denyDeleteCurrent", "true"), ("core.logAllRefUpdates", "always"),
                 ("gc.auto", "0"), ("receive.autogc", "false"), ("gc.pruneExpire", "never"),
                 ("gc.reflogExpire", "never"), ("gc.reflogExpireUnreachable", "never"))


def init_mirror(src: str, m: Path) -> None:
    m.parent.mkdir(parents=True, exist_ok=True)
    git("init", "--bare", "-q", str(m))
    ensure_config(m)
    code, head = git("symbolic-ref", "-q", "HEAD", cwd=src)
    if code == 0 and head.strip():
        git("symbolic-ref", "HEAD", head.strip(), cwd=m)
    ensure_hook(m)


def ensure_config(m: Path) -> None:
    """A run killed while creating a mirror leaves it without its settings: check the config file (no git call
    when it is complete) and apply any that are missing before anything is pushed."""
    try:
        text = (m / "config").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        text = ""
    for k, v in MIRROR_CONFIG:
        if f"{k.split('.', 1)[1].lower()} = {v}" not in text:
            git("config", k, v, cwd=m)


# git applies receive.denyDeletes and receive.denyNonFastForwards to refs/heads/* only; this per-ref hook refuses a
# delete or a non-fast-forward of ANY ref (tags, refs/rewritten/*, the canary). Found by the access check, 2026-10-31.
UPDATE_HOOK = """#!/bin/sh
# Backup mirror (Toolchain/backup): history may be added, never removed or rewritten.
ref="$1"; old="$2"; new="$3"
case "$new" in *[!0]*) ;; *) echo "backup mirror: refusing to delete $ref" >&2; exit 1 ;; esac
case "$old" in *[!0]*) ;; *) exit 0 ;; esac
[ "$old" = "$new" ] && exit 0
git merge-base --is-ancestor "$old" "$new" 2>/dev/null && exit 0
echo "backup mirror: refusing non-fast-forward update of $ref" >&2
exit 1
"""


def ensure_hook(m: Path) -> None:
    h = m / "hooks" / "update"
    if h.is_file() and h.read_text(encoding="utf-8", errors="replace") == UPDATE_HOOK:
        return
    h.parent.mkdir(exist_ok=True)
    if h.exists():
        run(["icacls", str(h), "/remove:d", EVERYONE, "/C", "/Q"])
    h.write_bytes(UPDATE_HOOK.encode("utf-8"))
    run(["icacls", str(h), "/deny", f"{EVERYONE}:(WD,AD,WEA,DE)", "/C", "/Q"])


def push(src: str, m: Path) -> str:
    """Push branches and tags. A branch the mirror refuses (non-fast-forward: amend, rebase) is kept as
    refs/rewritten/<branch>/<stamp> instead, a moved tag as refs/rewritten/tags/<tag>/<stamp>, once per object, so
    nothing is ever lost and nothing overwritten."""
    url = m.as_posix()
    code, out = git("push", "--porcelain", url, "refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*", cwd=src)
    kept, rejected, updated = [], [], 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        flag, refs, summary = parts[0].strip(), parts[1], parts[2]
        if flag in ("*", "+", " ") and "up to date" not in summary:
            updated += 1
        if flag == "!" and refs.startswith(("refs/heads/", "refs/tags/")):
            local = refs.split(":", 1)[0]
            branch = local[len("refs/heads/"):] if local.startswith("refs/heads/") else local[len("refs/"):]
            _, sha = git("rev-parse", local, cwd=src)
            sha = sha.strip()
            _, have = git("for-each-ref", "--format=%(objectname)", f"refs/rewritten/{branch}/", cwd=m)
            if sha in have.split():
                continue
            ref = f"refs/rewritten/{branch}/{dt.datetime.now():%Y%m%d-%H%M%S}"
            c2, o2 = git("push", "--porcelain", url, f"{sha}:{ref}", cwd=src)
            (kept if c2 == 0 else rejected).append(f"{branch}->{ref}" if c2 == 0 else f"{branch}: {o2.strip()[-200:]}")
        elif flag == "!":
            rejected.append(f"{refs}: {summary}")
    msg = f"{updated} ref(s) updated"
    if kept:
        msg += "; rewritten kept: " + ", ".join(kept)
    if rejected:
        msg += "; REJECTED: " + "; ".join(rejected)
    if code != 0 and not kept and not rejected and updated == 0 and "Everything up-to-date" not in out:
        msg = "push failed: " + out.strip()[-300:]
    return msg


def mirror_one(c: dict, name: str, src: str, init: bool) -> tuple[str, str]:
    if not (Path(src) / ".git").exists():
        return "skipped", "no .git (not a repo now)"
    code, refs = git("for-each-ref", "--count=1", "refs/heads", "refs/tags", cwd=src)
    if code != 0 and "not a git repository" in refs:
        return "skipped", "stale worktree or broken .git: " + refs.strip().splitlines()[-1].strip()
    if code == 0 and not refs.strip():
        return "skipped", "no commits yet"
    m = mirror_dir(c, name)
    if not m.is_dir():
        if not init:
            return "skipped", f"no mirror at {m} (the scheduled task creates it)"
        init_mirror(src, m)
    else:
        ensure_config(m)
    msg = push(src, m)
    return ("failed" if ("REJECTED" in msg or msg.startswith("push failed")) else "ok"), msg


def protect_mirror(m: Path) -> None:
    """Deny delete on the mirror folder and on every object and pack already written. Pushes still work: they only
    add new files; refs are replaced through their own (unprotected) files."""
    run(["icacls", str(m), "/deny", f"{EVERYONE}:(DE,DC)", "/C", "/Q"])
    if (m / "objects").is_dir():
        run(["icacls", str(m / "objects"), "/deny", f"{EVERYONE}:(DE,DC)", "/T", "/C", "/Q"], timeout=3600)


# ---------------------------------------------------------------- off-site (Rex, 2026-10-31: GitHub rs-* repos)

def offsite_url(c: dict, name: str) -> str:
    o = c.get("offsite", {})
    return o.get("base", "") + o.get("names", {}).get(name, f"rs-{name}") + ".git"


def offsite_state(c: dict) -> dict:
    f = root(c) / "logs" / "offsite.json"
    try:
        return json.loads(f.read_text(encoding="utf-8")) if f.is_file() else {}
    except ValueError:
        return {}


def refs_digest(m: Path) -> str:
    _, refs = git("for-each-ref", "--format=%(objectname) %(refname)", cwd=m)
    return hashlib.sha256(refs.encode()).hexdigest()[:16]


def offsite_push(c: dict, name: str) -> tuple[str, str]:
    """Push one local mirror's branches, tags and rewritten refs to its GitHub repo: never a delete, never a force.
    Skipped quietly when the repo does not exist there. Uses the machine's credential helper, never a stored token,
    and never prompts (a missing credential is a failure to report, not a login window)."""
    m = mirror_dir(c, name)
    if not m.is_dir():
        return "skipped", "no local mirror"
    url = offsite_url(c, name)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    code, out = git("ls-remote", "--heads", url, env=env)
    if code != 0:
        if "not found" in out.lower() or "does not appear to be a git repository" in out:
            return "skipped", f"{url} does not exist"
        return "failed", f"cannot reach {url}: {out.strip()[-200:]}"
    code, out = git("push", "--porcelain", url, "refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*",
                    "refs/rewritten/*:refs/rewritten/*", cwd=m, env=env)
    bad = [l for l in out.splitlines() if l.startswith("!")]
    if code != 0 or bad:
        return "failed", "; ".join(bad)[-300:] or out.strip()[-300:]
    return "ok", f"pushed to {url}"


def offsite_all(c: dict, only: str | None = None) -> list[str]:
    """The off-site step of the job (never the belt hook: it writes the state file under the backup root)."""
    st, lines = offsite_state(c), []
    now = dt.datetime.now().isoformat(timespec="seconds")
    used: dict[str, str] = {}
    for n in ([only] if only else list(platform_repos(c))):
        url = offsite_url(c, n)
        if url in used:  # e.g. realism -> rs-life while a `life` repo also exists: never mix two histories
            result, msg = "failed", f"{url} is already {used[url]}'s off-site repo; give {n} its own in config offsite.names"
        else:
            result, msg = offsite_push(c, n)
            if result != "skipped":
                used[url] = n
        if result != "skipped" or n in st:
            lines.append(f"offsite {n}: {result}: {msg}")
        if result == "ok":
            st[n] = {"at": now, "refs": refs_digest(mirror_dir(c, n)), "url": offsite_url(c, n)}
        elif result == "failed":
            st.setdefault(n, {})["last_failure"] = {"at": now, "msg": msg}
    f = root(c) / "logs" / "offsite.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(st, indent=1), encoding="utf-8")
    return lines


def cmd_mirror(a, c) -> int:
    rs = repos(c)
    if a.path:
        hits = [(n, p) for n, p in rs.items() if norm(p) == norm(a.path)]
        if not hits:
            print(f"backup: {a.path} is not a configured repo; nothing mirrored")
            return 0
        targets = hits
    elif a.repo:
        targets = [(a.repo, rs[a.repo])]
    else:
        targets = list(rs.items())
    bad = 0
    for n, p in targets:
        state, msg = mirror_one(c, n, p, a.init)
        bad += state == "failed"
        print(f"backup: mirror {n}: {state}: {msg}")
    return 1 if bad else 0


# ---------------------------------------------------------------- snapshots

def sources(c: dict) -> list[tuple[str, str, set[str]]]:
    """(name, path, extra excluded dir names). A source is a path, or {"path": ..., "exclude": [...]}."""
    out = []
    for n, v in c["snapshot_sources"].items():
        if isinstance(v, dict):
            out.append((n, v["path"], set(v.get("exclude", []))))
        else:
            out.append((n, v, set()))
    return out


def source_path(c: dict, name: str) -> str:
    return next((p for n, p, _ in sources(c) if n == name), "")


def snaps(c: dict, complete: bool = True) -> list[Path]:
    """Dated snapshot folders, oldest first. A snapshot is complete once its MANIFEST.json exists (written last)."""
    d = root(c) / "snap"
    found = sorted(p for p in d.iterdir() if p.is_dir() and re.fullmatch(r"\d{4}-\d\d-\d\d-\d{4}(-\d\d)?", p.name)) if d.is_dir() else []
    return [p for p in found if (p / "MANIFEST.json").is_file() == complete]


def copy_tree(src: Path, dst: Path, prev: Path | None, ex: set[str], st: dict, rel: str = "") -> None:
    dst.mkdir(parents=True, exist_ok=True)
    try:
        entries = list(os.scandir(src))
    except OSError as e:
        st["errors"].append(f"{rel or src}: {e}")
        return
    for e in entries:
        r = f"{rel}/{e.name}" if rel else e.name
        try:
            s = e.stat(follow_symlinks=False)
        except OSError as err:
            st["errors"].append(f"{r}: {err}")
            continue
        if getattr(s, "st_file_attributes", 0) & REPARSE:
            st["links_skipped"].append(r)
            continue
        if e.is_dir(follow_symlinks=False):
            if e.name not in ex:
                copy_tree(Path(e.path), dst / e.name, prev / e.name if prev else None, ex, st, r)
            continue
        out = dst / e.name
        if prev is not None:
            pf = prev / e.name
            try:
                ps = pf.stat()
                if ps.st_size == s.st_size and ps.st_mtime_ns == s.st_mtime_ns:
                    os.link(pf, out)
                    st["linked"] += 1
                    continue
            except OSError:
                pass
        try:
            shutil.copy2(e.path, out)
            st["copied"] += 1
            st["bytes"] += s.st_size
        except OSError as err:
            st["errors"].append(f"{r}: {err}")


def bundle_mirrors(c: dict, snap: Path, prev: Path | None, st: dict) -> None:
    """A git bundle of every mirror inside the snapshot, so mirror history is also delete-protected. Unchanged refs
    hard-link the previous snapshot's bundle."""
    gdir = snap / "git"
    gdir.mkdir(exist_ok=True)
    for m in sorted((root(c) / "git").glob("*.git")):
        name = m.name[:-4]
        _, refs = git("for-each-ref", "--format=%(objectname) %(refname)", cwd=m)
        if not refs.strip():
            continue
        (gdir / f"{name}.refs").write_text(refs, encoding="utf-8")
        pb = prev / "git" / f"{name}.bundle" if prev else None
        if pb and pb.is_file() and (prev / "git" / f"{name}.refs").read_text(encoding="utf-8") == refs:
            try:
                os.link(pb, gdir / f"{name}.bundle")
                st["bundles_linked"] += 1
                continue
            except OSError:
                pass
        code, out = git("bundle", "create", str(gdir / f"{name}.bundle"), "--all", cwd=m)
        if code == 0:
            st["bundles"] += 1
        else:
            st["errors"].append(f"bundle {name}: {out.strip()[-200:]}")


def rmtree(p: Path) -> None:
    """shutil.rmtree that clears the read-only bit git sets on objects, and waits out a scanner briefly holding a
    just-written file (WinError 32). Callers check for reparse points first or hold a tree this script wrote."""
    def again(fn, path, _exc):
        try:
            os.chmod(path, 0o666)
        except OSError:
            pass
        for i in range(8):
            try:
                fn(path)
                return
            except PermissionError:
                if i == 7:
                    raise
                time.sleep(0.5 * (i + 1))
    shutil.rmtree(p, onerror=again)


SNAP_DENY = "(DE,DC,WD,AD,WEA)"  # no delete, no write/append (or add file/subfolder), no extended-attribute writes;
                                 # write-attributes stays allowed: the next snapshot hard-links these files


def protect(p: Path) -> int:
    code, _ = run(["icacls", str(p), "/deny", f"{EVERYONE}:{SNAP_DENY}", "/T", "/C", "/Q"], timeout=3600)
    return code


def unprotect(p: Path) -> int:
    code, _ = run(["icacls", str(p), "/remove:d", EVERYONE, "/T", "/C", "/Q"], timeout=3600)
    return code


def cmd_snapshot(a, c) -> int:
    base = root(c) / "snap"
    base.mkdir(parents=True, exist_ok=True)
    now = getattr(a, "now", None) or dt.datetime.now()  # tests pass an old time instead of renaming a snapshot
    name = now.strftime(STAMP)
    if (base / name).exists():
        name = now.strftime(STAMP + "-%S")
    prev = (snaps(c) or [None])[-1]
    for p in snaps(c, complete=False):  # an interrupted run: its hard links share the previous snapshot's files
        unprotect(p)
        rmtree(p)
        if prev:
            protect(prev)
    work = base / name
    st = {"copied": 0, "linked": 0, "bytes": 0, "bundles": 0, "bundles_linked": 0, "errors": [], "links_skipped": []}
    ex = set(c["exclude_dirs"])
    for sname, spath, extra in sources(c):
        if Path(spath).is_dir():
            copy_tree(Path(spath), work / sname, prev / sname if prev else None, ex | extra, st)
        else:
            st["errors"].append(f"source missing: {sname} {spath}")
    bundle_mirrors(c, work, prev, st)
    manifest = {"name": name, "at": now.isoformat(timespec="seconds"), "previous": prev.name if prev else None,
                "sources": c["snapshot_sources"], "exclude_dirs": sorted(ex), **st,
                "errors": st["errors"][:200], "error_count": len(st["errors"]),
                "links_skipped": st["links_skipped"][:200], "links_skipped_count": len(st["links_skipped"])}
    (work / CANARY).write_text("access-check target: write, append, delete and ACL changes must all fail\n", encoding="utf-8")
    (work / "MANIFEST.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    pc = protect(work)
    print(f"backup: snapshot {name}: {st['copied']} copied ({st['bytes'] / 1e6:.1f} MB), {st['linked']} linked, "
          f"{st['bundles']} bundles (+{st['bundles_linked']} linked), {len(st['errors'])} errors, "
          f"{len(st['links_skipped'])} links skipped, protect exit {pc}")
    return 0 if pc == 0 else 1


def keep_set(names: list[str], now: dt.datetime, r: dict) -> set[str]:
    """Newest always; everything within all_hours; newest per hour within hourly_days; newest per day within daily_days."""
    keep, hours, days = set(), set(), set()
    for n in sorted(names, reverse=True):
        t = dt.datetime.strptime(n[:15], STAMP)
        age = now - t
        if not keep:
            keep.add(n)
        if age <= dt.timedelta(hours=r["all_hours"]):
            keep.add(n)
        elif age <= dt.timedelta(days=r["hourly_days"]) and t.strftime("%Y%m%d%H") not in hours:
            keep.add(n)
        elif age <= dt.timedelta(days=r["daily_days"]) and t.strftime("%Y%m%d") not in days:
            keep.add(n)
        hours.add(t.strftime("%Y%m%d%H"))
        days.add(t.strftime("%Y%m%d"))
    return keep


def cmd_prune(a, c) -> int:
    all_snaps = snaps(c)
    keep = keep_set([p.name for p in all_snaps], dt.datetime.now(), c["retention"])
    doomed = [p for p in all_snaps if p.name not in keep]
    for p in doomed:
        if a.dry:
            print(f"backup: would prune {p.name}")
            continue
        unprotect(p)
        rmtree(p)
        # Hard-linked files are shared with neighbours, and lifting the deny lifted it on the shared file: re-protect
        # the nearest kept snapshot on each side (a shared file always sits in a contiguous run of snapshots).
        rest = snaps(c)
        older = [q for q in rest if q.name < p.name][-1:]
        newer = [q for q in rest if q.name > p.name][:1]
        for q in older + newer:
            protect(q)
        print(f"backup: pruned {p.name}")
    return 0


# ---------------------------------------------------------------- status

def last_restore_test(c: dict) -> dict | None:
    f = Path(c.get("restore_test_log", HERE / "logs" / "restore-test.jsonl"))
    if not f.is_file():
        return None
    rows = [l for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
    return json.loads(rows[-1]) if rows else None


def mirror_state(c: dict, name: str, src: str) -> dict:
    m = mirror_dir(c, name)
    d = {"repo": name, "mirrored": m.is_dir(), "is_repo": (Path(src) / ".git").exists(), "last": None, "covered": None}
    if not m.is_dir():
        return d
    logs = [p for p in (m / "logs").rglob("*") if p.is_file()] if (m / "logs").is_dir() else []
    if logs:
        d["last"] = dt.datetime.fromtimestamp(max(p.stat().st_mtime for p in logs)).isoformat(timespec="minutes")
    if d["is_repo"]:
        _, head = git("rev-parse", "HEAD", cwd=src)
        code, _ = git("cat-file", "-e", f"{head.strip()}^{{commit}}", cwd=m)
        d["covered"] = code == 0
    return d


def status(c: dict | None = None, detail_all: bool = False) -> dict:
    c = c or cfg()
    rs = repos(c)
    plat = platform_repos(c)
    platform = [mirror_state(c, n, p) for n, p in plat.items()]
    belt = [n for n in rs if n not in plat]
    belt_mirrored = sum(1 for n in belt if mirror_dir(c, n).is_dir())
    ss = snaps(c)
    latest = None
    if ss:
        try:
            latest = json.loads((ss[-1] / "MANIFEST.json").read_text(encoding="utf-8"))
            latest = {k: latest.get(k) for k in ("name", "at", "copied", "linked", "error_count", "links_skipped_count")}
        except (OSError, ValueError):
            latest = {"name": ss[-1].name}
    lr = root(c) / "logs" / "last-run.json"
    # Recovery point objective (Rex, 2026-10-31): minutes of completed work a loss right now would cost. Files: time
    # since the latest snapshot started. Commits: for a platform repo whose HEAD is not in its mirror, time since
    # that HEAD was committed. The larger is the RPO; target 30 minutes.
    now = dt.datetime.now()
    rpo = {"snapshot_min": None, "unmirrored": [], "minutes": None, "target": 30}
    if latest and latest.get("at"):
        rpo["snapshot_min"] = round((now - dt.datetime.fromisoformat(latest["at"])).total_seconds() / 60)
    for p in platform:
        if p["is_repo"] and not p["covered"]:
            _, ct = git("log", "-1", "--format=%ct", cwd=plat[p["repo"]])
            if ct.strip().isdigit():
                rpo["unmirrored"].append({"repo": p["repo"], "minutes": round((now.timestamp() - int(ct)) / 60)})
    ages = ([rpo["snapshot_min"]] if rpo["snapshot_min"] is not None else []) + [u["minutes"] for u in rpo["unmirrored"]]
    rpo["minutes"] = max(ages) if ages else None
    # Off-site: per platform repo, the last GitHub push; a repo whose local mirror moved since then has been at risk
    # (if this machine is lost) since that push. Reported beside the local RPO, not inside it, while it is off.
    off = {"enabled": bool(c.get("offsite", {}).get("enabled")), "repos": [], "minutes": None}
    ost = offsite_state(c)
    for n in plat:
        s = ost.get(n, {})
        stale = None
        if s.get("at") and mirror_dir(c, n).is_dir() and refs_digest(mirror_dir(c, n)) != s.get("refs"):
            stale = round((now - dt.datetime.fromisoformat(s["at"])).total_seconds() / 60)
        off["repos"].append({"repo": n, "last": s.get("at"), "behind_min": stale or 0 if s.get("at") else None,
                             "failure": (s.get("last_failure") or {}).get("msg")})
    known = [r["behind_min"] for r in off["repos"] if r["behind_min"] is not None]
    off["minutes"] = max(known) if known else None
    if off["enabled"] and off["minutes"] is not None:
        rpo["minutes"] = max(rpo["minutes"] or 0, off["minutes"])
    return {"root": str(root(c)), "platform": platform, "belt_repos": len(belt), "belt_mirrored": belt_mirrored,
            "snapshots": len(ss), "latest_snapshot": latest, "rpo": rpo, "offsite": off,
            "last_run": json.loads(lr.read_text(encoding="utf-8")) if lr.is_file() else None,
            "restore_test": last_restore_test(c)}


# ---------------------------------------------------------------- restore

def has_reparse(p: Path) -> list[str]:
    hits = []
    for dp, dns, fns in os.walk(p):
        for n in dns + fns:
            try:
                if os.lstat(os.path.join(dp, n)).st_file_attributes & REPARSE:
                    hits.append(os.path.join(dp, n))
            except OSError:
                pass
        dns[:] = [d for d in dns if os.path.join(dp, d) not in hits]
    return hits


def task_repo(md: Path) -> str | None:
    try:
        for line in md.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
            m = re.match(r"^Repo:\s*(.+?)\s*$", line)
            if m:
                return m.group(1)
    except OSError:
        pass
    return None


def units_after(c: dict, src: str, dest: Path) -> list[str]:
    """Belt units that passed in this repo whose commit the restored clone lacks: replay these."""
    q = Path(source_path(c, "belt-queue"))
    games = q.parent.parent
    out = []
    for f in q.glob("*/logs/results.jsonl") if q.is_dir() else []:
        lane = f.parent.parent
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not row.get("ok") or not row.get("head_after"):
                continue
            md = lane / "done" / f"{row['name']}.md"
            rp = task_repo(md) if md.is_file() else None
            if not rp or norm((games / rp) if not os.path.isabs(rp) else rp) != norm(src):
                continue
            code, _ = git("cat-file", "-e", f"{row['head_after']}^{{commit}}", cwd=dest)
            if code != 0:
                out.append(f"{lane.name}/{row['name']} (head {row['head_after'][:7]}, passed {row.get('at')})")
    return out


def snapshot_repo(c: dict, snap: Path, src: str) -> Path | None:
    for sname, spath, _ in sources(c):
        if norm(src) == norm(spath) or norm(src).startswith(norm(spath) + os.sep):
            rel = os.path.relpath(src, spath)
            p = snap / sname / ("" if rel == "." else rel)
            return p if p.is_dir() else None
    return None


def restore(c: dict, name: str, snapshot: str | None = None, dest: Path | None = None, gates: bool = True) -> dict:
    rs = repos(c)
    src = rs[name]
    m = mirror_dir(c, name)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = Path(dest or Path(r"E:\AI Programs\_restore") / f"{name}-{stamp}")
    rep = {"repo": name, "dest": str(dest), "at": dt.datetime.now().isoformat(timespec="seconds"), "steps": []}
    say = rep["steps"].append
    if dest.exists():
        raise SystemExit(f"restore: {dest} exists; restore only into a fresh path")
    if not m.is_dir():
        raise SystemExit(f"restore: no mirror for {name} at {m}")
    # --no-hardlinks: a local clone would otherwise share the mirror's object files, and with them its deny-delete ACE
    # core.autocrlf=false: the restore holds the committed bytes, whatever this machine's global setting is
    code, out = git("clone", "-q", "--no-hardlinks", "--no-checkout", "-c", "core.autocrlf=false", m.as_posix(), str(dest))
    if code != 0:
        raise SystemExit(f"restore: clone failed: {out}")
    git("fetch", "-q", "origin", "+refs/rewritten/*:refs/rewritten/*", cwd=dest)
    _, head = git("symbolic-ref", "-q", "--short", "HEAD", cwd=m)
    branch = head.strip() or "main"
    cands = [f"refs/remotes/origin/{branch}"]
    _, rw = git("for-each-ref", "--sort=-committerdate", "--format=%(refname)", f"refs/rewritten/{branch}/", cwd=dest)
    cands += rw.split()[:1]
    _, best = git("for-each-ref", "--sort=-committerdate", "--count=1", "--format=%(objectname)", *cands, cwd=dest)
    commit = best.strip()
    say(f"mirror: branch {branch} at {commit[:7]}" + (f" (newer rewritten ref {rw.split()[0]})" if rw.split() and rw.split()[0] else ""))
    ss = snaps(c)
    snap = next((p for p in ss if p.name == snapshot), None) if snapshot else (ss[-1] if ss else None)
    rep["snapshot"] = snap.name if snap else None
    srepo = snapshot_repo(c, snap, src) if snap else None
    patch, untracked = b"", []
    if srepo and (srepo / ".git").is_dir():
        git("fetch", "-q", "--no-tags", str(srepo), "+refs/heads/*:refs/snapshot/*", cwd=dest)
        _, s_head = git("--git-dir", str(srepo / ".git"), "rev-parse", "HEAD")
        s_head = s_head.strip()
        if s_head and s_head != commit and git("merge-base", "--is-ancestor", commit, s_head, cwd=dest)[0] == 0:
            say(f"snapshot {snap.name} has later commits than the mirror: using its HEAD {s_head[:7]}")
            commit = s_head
        # Uncommitted work at snapshot time, read without writing into the protected snapshot (temp index copy).
        with tempfile.TemporaryDirectory() as td:
            idx = Path(td) / "index"
            if (srepo / ".git" / "index").is_file():
                shutil.copy2(srepo / ".git" / "index", idx)
            env = {**os.environ, "GIT_INDEX_FILE": str(idx), "GIT_OPTIONAL_LOCKS": "0"}
            base = ["--git-dir", str(srepo / ".git"), "--work-tree", str(srepo)]
            _, patch = git_out(*base, "diff", "--binary", "HEAD", env=env)
            _, ut = git_out(*base, "ls-files", "-z", "--others", "--exclude-standard", env=env)
            untracked = [u for u in ut.decode("utf-8", "replace").split("\0") if u]
            rep["snapshot_head"] = s_head
    elif snap:
        say(f"snapshot {snap.name} holds no copy of this repo's .git; no uncommitted files to reapply")
    git("checkout", "-q", "-B", branch, commit, cwd=dest)
    rep["commit"] = commit
    if patch.strip():
        pf = dest.parent / f".{dest.name}.patch"
        pf.write_bytes(patch)
        mode = [] if commit == rep.get("snapshot_head") else ["--3way"]
        code, out = git("apply", "--binary", *mode, str(pf), cwd=dest)
        say(f"reapplied uncommitted changes from {snap.name}: " + ("ok" if code == 0 else "CONFLICT: " + out.strip()[-300:]))
        pf.unlink()
    copied = 0
    for u in untracked:
        t = dest / u
        if not t.exists():
            t.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(srepo / u, t)
            copied += 1
    if untracked:
        say(f"copied {copied} of {len(untracked)} untracked files from the snapshot")
    rep["replay"] = units_after(c, src, dest)
    say(f"belt units passed after the restored commit (replay them): {len(rep['replay'])}")
    rep["gates"] = []
    if gates:
        if (dest / "package-lock.json").is_file():
            code, out = run(["cmd", "/c", "npm", "ci", "--offline", "--no-audit", "--no-fund"], cwd=dest, timeout=1800)
            say(f"npm ci --offline: exit {code}" + ("" if code == 0 else ": " + out.strip()[-300:]))
        for g in c.get("gates", {}).get(name, []):
            code, out = run(["cmd", "/c", *g.split()], cwd=dest, timeout=3600)
            tests = re.findall(r"Tests\s+(\d+) passed", re.sub(r"\x1b\[[0-9;]*m", "", out))
            rep["gates"].append({"cmd": g, "exit": code, "tests_passed": int(tests[-1]) if tests else None,
                                 "tail": re.sub(r"\x1b\[[0-9;]*m", "", out).strip()[-600:]})
            say(f"gate `{g}`: exit {code}" + (f", {tests[-1]} tests passed" if tests else ""))
    return rep


def file_hash(p: Path, eol: bool = False) -> str:
    """sha256 of the file; with eol=True, of its bytes with CRLF read as LF (a checkout's line endings are not content)."""
    if eol:
        return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def restore_test(c: dict, keep: bool = False) -> dict:
    t = c["restore_test"]
    name = t["repo"]
    src = repos(c)[name]
    row = {"at": dt.datetime.now().isoformat(timespec="seconds"), "repo": name, "pass": False}
    if not mirror_dir(c, name).is_dir():
        row["reason"] = f"no mirror for {name} (its .git must exist before the first mirror)"
    else:
        dest = Path(r"E:\AI Programs\_caches\tmp\restore-test") / f"{name}-{dt.datetime.now():%Y%m%d-%H%M%S}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            rep = restore(c, name, dest=dest)
        except SystemExit as e:
            rep = {"steps": [str(e)], "gates": []}
        row.update({"commit": rep.get("commit"), "snapshot": rep.get("snapshot"), "steps": rep["steps"],
                    "replay": len(rep.get("replay", [])), "gates": [{k: g[k] for k in ("cmd", "exit", "tests_passed")} for g in rep["gates"]]})
        # Hash compare: every tracked file in the restore against the live tree. A live file changed after the
        # snapshot is drift (newer work), not a restore error.
        snap_t = dt.datetime.fromisoformat(json.loads((snaps(c)[-1] / "MANIFEST.json").read_text(encoding="utf-8"))["at"]).timestamp() if snaps(c) else 0
        mism, drift, missing = [], [], []
        if dest.is_dir():
            _, files = git("ls-files", "-z", cwd=dest)
            for f in [x for x in files.split("\0") if x]:
                lf = Path(src) / f
                if not lf.is_file():
                    missing.append(f)
                elif file_hash(lf) != file_hash(dest / f) and file_hash(lf, eol=True) != file_hash(dest / f, eol=True):
                    (drift if lf.stat().st_mtime > snap_t else mism).append(f)
        row.update({"files_compared": len(files.split("\0")) - 1 if dest.is_dir() else 0, "mismatch": mism[:50],
                    "drift_since_snapshot": drift[:50], "missing_in_live": missing[:50]})
        gates_ok = bool(rep["gates"]) and all(g["exit"] == 0 for g in rep["gates"])
        counts = [g["tests_passed"] for g in rep["gates"] if g["tests_passed"] is not None]
        count_ok = bool(counts) and max(counts) >= t.get("expect_tests", 0)
        row["pass"] = gates_ok and count_ok and not mism
        row["reason"] = "ok" if row["pass"] else "; ".join(
            x for x in (None if gates_ok else "a gate failed", None if count_ok else f"tests {counts} < {t.get('expect_tests')}",
                        None if not mism else f"{len(mism)} file(s) differ from live") if x)
        if not keep and dest.is_dir():
            links = has_reparse(dest)
            if links:
                row["cleanup"] = f"left in place: {len(links)} junction/symlink(s) inside, never removed by script"
            else:
                try:
                    rmtree(dest)
                    row["cleanup"] = "removed"
                except OSError as e:
                    row["cleanup"] = f"left in place: {e}"
        else:
            row["cleanup"] = f"kept at {dest}"
    row["access"] = access_check(c)  # Rex 2026-10-31: the restore test includes the hostile-access attempts
    f = Path(c.get("restore_test_log", HERE / "logs" / "restore-test.jsonl"))
    f.parent.mkdir(parents=True, exist_ok=True)
    with open(f, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


# ---------------------------------------------------------------- access check (Rex, 2026-10-31)

CANARY = "CANARY.txt"
CANARY_REF = "refs/canary/backup"


def whoami() -> str:
    _, out = run(["whoami"])
    return out.strip()


def ensure_canary_ref(m: Path) -> None:
    """The mirror's access-check target: a ref nothing else uses, recreated by the scheduled task when missing."""
    if git("rev-parse", "-q", "--verify", CANARY_REF, cwd=m)[0] != 0:
        code, head = git("rev-parse", "-q", "--verify", "HEAD", cwd=m)
        if code == 0:
            git("update-ref", CANARY_REF, head.strip(), cwd=m)


def access_check(c: dict) -> dict:
    """Attempt, as the account running this, what a build agent must not be able to do to the backups: change and
    delete a snapshot file, rename a snapshot, delete a mirror ref (by push and by direct ref edit), and lift the
    deny ACE. Every attempt must be refused. Anything that gets through is put back at once and reported."""
    res = {"at": dt.datetime.now().isoformat(timespec="seconds"), "account": whoami(), "checks": []}

    def check(what: str, attempt) -> None:
        try:
            ok, note = attempt()
        except OSError as e:
            ok, note = False, type(e).__name__
        res["checks"].append({"attempt": what, "result": "ALLOWED" if ok else "refused", "note": note})

    snap = next((p for p in reversed(snaps(c)) if (p / CANARY).is_file()), None)
    if snap:
        can = snap / CANARY

        def append():
            with open(can, "a", encoding="utf-8") as fh:
                fh.write("tampered\n")
            return True, f"{snap.name}/{CANARY}"

        def delete():
            os.unlink(can)
            can.write_text("access-check target (recreated after a successful delete)\n", encoding="utf-8")
            return True, f"{snap.name}/{CANARY}"

        def rename():
            moved = snap.with_name(snap.name + "-moved")
            os.rename(snap, moved)
            os.rename(moved, snap)
            return True, snap.name

        def lift_acl():
            code, out = run(["icacls", str(can), "/remove:d", EVERYONE, "/C"])
            lifted = code == 0 and "Successfully processed 1" in out
            if lifted:
                run(["icacls", str(can), "/deny", f"{EVERYONE}:{SNAP_DENY}", "/C", "/Q"])
            return lifted, "icacls /remove:d (deny re-applied at once)" if lifted else out.strip()[-120:]

        check("append to a snapshot file", append)
        check("delete a snapshot file", delete)
        check("rename a snapshot folder", rename)
        check("remove the snapshot's deny ACE (owner's WRITE_DAC)", lift_acl)
    else:
        res["checks"].append({"attempt": "snapshot checks", "result": "not run", "note": f"no snapshot with {CANARY} yet"})
    m = mirror_dir(c, c["restore_test"]["repo"])
    code, sha = git("rev-parse", "-q", "--verify", CANARY_REF, cwd=m) if m.is_dir() else (1, "")
    if code == 0:
        sha = sha.strip()

        def push_delete():
            code, out = git("push", "--porcelain", m.as_posix(), f":{CANARY_REF}", cwd=m)
            return code == 0 and git("rev-parse", "-q", "--verify", CANARY_REF, cwd=m)[0] != 0, out.strip()[-120:]

        def direct_delete():
            code, out = git("update-ref", "-d", CANARY_REF, cwd=m)
            gone = git("rev-parse", "-q", "--verify", CANARY_REF, cwd=m)[0] != 0
            if gone:
                git("update-ref", CANARY_REF, sha, cwd=m)
            return gone, "git update-ref -d in the mirror (ref restored at once)" if gone else out.strip()[-120:]

        check(f"delete mirror ref {CANARY_REF} by push", push_delete)
        check(f"delete mirror ref {CANARY_REF} by editing the mirror", direct_delete)
    else:
        res["checks"].append({"attempt": "mirror checks", "result": "not run", "note": f"no {CANARY_REF} in {m.name} yet"})
    ran = [x for x in res["checks"] if x["result"] != "not run"]
    res["pass"] = bool(ran) and all(x["result"] == "refused" for x in res["checks"])
    res["allowed"] = [x["attempt"] for x in res["checks"] if x["result"] == "ALLOWED"]
    return res


# ---------------------------------------------------------------- the scheduled job

def cmd_run(a, c) -> int:
    logd = root(c) / "logs"
    logd.mkdir(parents=True, exist_ok=True)
    t0 = dt.datetime.now()
    lines, mirrors = [], {}
    plat = platform_repos(c)

    def mirror_set(names: dict[str, str]) -> None:
        for n, p in names.items():
            m = mirror_dir(c, n)
            new = not m.is_dir()
            state, msg = mirror_one(c, n, p, init=True)
            mirrors[n] = state
            if state != "skipped" or n in plat:
                lines.append(f"mirror {n}: {state}: {msg}")
            if m.is_dir():
                ensure_hook(m)
                if n == c["restore_test"]["repo"]:
                    ensure_canary_ref(m)
                # icacls /T over a mirror's objects is the slow part: only where something was written this run
                if new or not msg.startswith("0 ref(s) updated"):
                    protect_mirror(m)

    # Order (BKP-17): the platform repos, then the snapshot (the recovery point the RPO measures), then the belt's
    # game repos, of which there are 120+ and growing, so they can never delay the snapshot.
    mirror_set(plat)
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        sc = cmd_snapshot(a, c)
        cmd_prune(argparse.Namespace(dry=False), c)
    lines += buf.getvalue().splitlines()
    mirror_set({n: p for n, p in repos(c).items() if n not in plat})
    if c.get("offsite", {}).get("enabled"):
        lines += offsite_all(c)
    rt = last_restore_test(c)
    due = not rt or not rt.get("pass") or (dt.datetime.now() - dt.datetime.fromisoformat(rt["at"])).days >= c["restore_test"]["every_days"]
    # Once a dedicated account runs this job (HQ/handoffs/backup/HANDOFF.md §5), the restore test and the access
    # check move to a task that runs as the agent account: set both switches false in config.json.
    if c.get("restore_test_in_run", True) and due and mirror_dir(c, c["restore_test"]["repo"]).is_dir():
        r = restore_test(c)
        lines.append(f"restore test {r['repo']}: {'PASS' if r['pass'] else 'FAIL'}: {r.get('reason')}")
    acc = None
    if c.get("access_check_in_run", True):
        acc = access_check(c)
        lines.append(f"access check as {acc['account']}: {'PASS' if acc['pass'] else 'FAIL'}"
                     + (f": allowed {', '.join(acc['allowed'])}" if acc["allowed"] else ""))
    summary = {"at": t0.isoformat(timespec="seconds"), "seconds": round((dt.datetime.now() - t0).total_seconds()),
               "mirrors_ok": sum(v == "ok" for v in mirrors.values()), "mirrors_failed": sum(v == "failed" for v in mirrors.values()),
               "failed": [n for n, v in mirrors.items() if v == "failed"], "snapshot_exit": sc, "access": acc}
    with open(logd / f"run-{t0:%Y-%m}.log", "a", encoding="utf-8") as fh:
        fh.write(f"=== {t0:%Y-%m-%d %H:%M:%S} ({summary['seconds']}s)\n" + "\n".join(lines) + "\n")
    (logd / "last-run.json").write_text(json.dumps(summary), encoding="utf-8")
    return 0 if sc == 0 and summary["mirrors_failed"] == 0 else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mirror")
    m.add_argument("--path")
    m.add_argument("--repo")
    m.add_argument("--all", action="store_true")
    m.add_argument("--init", action="store_true")
    sub.add_parser("snapshot")
    p = sub.add_parser("prune")
    p.add_argument("--dry", action="store_true")
    sub.add_parser("run")
    sub.add_parser("status")
    r = sub.add_parser("restore")
    r.add_argument("repo")
    r.add_argument("--snapshot")
    r.add_argument("--dest")
    r.add_argument("--no-gates", action="store_true")
    t = sub.add_parser("restore-test")
    t.add_argument("--keep", action="store_true")
    sub.add_parser("access-check")
    o = sub.add_parser("offsite")
    o.add_argument("--repo")
    a = ap.parse_args(argv)
    c = cfg()
    if a.cmd == "mirror":
        if not (a.path or a.repo or a.all):
            ap.error("mirror needs --path, --repo or --all")
        return cmd_mirror(a, c)
    if a.cmd == "snapshot":
        return cmd_snapshot(a, c)
    if a.cmd == "prune":
        return cmd_prune(a, c)
    if a.cmd == "run":
        return cmd_run(a, c)
    if a.cmd == "status":
        print(json.dumps(status(c), indent=1))
        return 0
    if a.cmd == "restore":
        rep = restore(c, a.repo, a.snapshot, Path(a.dest) if a.dest else None, gates=not a.no_gates)
        print(json.dumps(rep, indent=1))
        return 0 if all(g["exit"] == 0 for g in rep["gates"]) else 1
    if a.cmd == "restore-test":
        row = restore_test(c, keep=a.keep)
        print(json.dumps(row, indent=1))
        return 0 if row["pass"] else 1
    if a.cmd == "offsite":
        if not c.get("offsite", {}).get("enabled"):
            print("backup: off-site push is disabled (config offsite.enabled); nothing pushed")
            return 0
        lines = offsite_all(c, a.repo)
        print("\n".join(lines))
        return 1 if any(": failed:" in l for l in lines) else 0
    if a.cmd == "access-check":
        res = access_check(c)
        print(json.dumps(res, indent=1))
        return 0 if res["pass"] else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
