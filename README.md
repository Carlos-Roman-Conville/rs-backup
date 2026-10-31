# Backup and recovery (Toolchain/backup)

Rex's decision after I-1048 (2026-10-30): the pipeline recovers itself from frequent, independently protected
checkpoints. Spec: `HQ/handoffs/controller/BACKUP.md`. Keeper: backup keeper (`HQ/handoffs/backup/`).

## What exists

| Piece | Where | How |
|---|---|---|
| Git mirrors | `E:\backups\reality-sim\git\<repo>.git` | bare; `receive.denyDeletes`, `receive.denyNonFastForwards` (git applies these to branches only) plus an `update` hook refusing any delete or non-fast-forward of any ref; reflogs always, `gc.auto 0`. Branches and tags pushed; a branch the mirror refuses (amend, rebase) is kept as `refs/rewritten/<branch>/<stamp>`, a moved tag as `refs/rewritten/tags/<tag>/<stamp>`. Objects and the folder are deny-delete for Everyone. |
| Repos | `config.json` `repos` (platform) + every git repo in `Games/Card Games/_agent/repos.txt` | a repo without `.git` is skipped until it has one |
| Belt hook | `run_queue.py` `finish()` → `mirror_push()` | after every passing unit: `backup.py mirror --path <repo>` from the protected copy; pushes to an existing mirror only; any error is one log line, never a verdict |
| Snapshots | `E:\backups\reality-sim\snap\<yyyy-mm-dd-HHMM>\` | `Toolchain` (no `node_modules`, `.codex-runs`), `HQ`, the belt queue, pirate `files` and `data`, plus a `git\<repo>.bundle` of every mirror. Unchanged files are hard links to the previous snapshot. Junctions and symlinks are never followed (listed in `MANIFEST.json`). `icacls /deny Everyone:(DE,DC,WD,AD,WEA) /T` once written (no delete, write or append; hard links still work). |
| Retention | `config.json` `retention` | everything 24 h, newest per hour 7 days, newest per day 60 days; only `run` prunes; pruning lifts the deny on what it retires and re-protects the neighbours that share hard links |
| Scheduled task | `\RealitySim\Backup`, every 30 min, current user | runs `E:\backups\reality-sim\bin\backup.py run` (a copy denied write and delete, refreshed by `install.ps1`): mirror all, protect mirrors, snapshot, prune, restore test weekly or after a failed one. Log: `E:\backups\reality-sim\logs\run-<yyyy-mm>.log`, `last-run.json` |
| Restore | `restore.ps1 <repo> [-Snapshot NAME] [-Dest DIR] [-NoGates] [-InPlace]` | clone the mirror (newest of branch and its rewritten refs) into a fresh folder; take later commits from the snapshot's `.git` if they descend; reapply the snapshot's uncommitted and untracked files; list belt units passed after the restored commit (replay them); `npm ci --offline`; run `config.json` `gates`. `-InPlace` swaps it in only after you type the repo name; the live folder is renamed aside, never deleted |
| Restore test | `restore-test.ps1 [-Keep]` | restores the kernel into `_caches\tmp\restore-test\`, runs its gates (expects 149 tests), hashes every tracked file against the live tree (a live file newer than the snapshot is drift, not failure), appends to `logs\restore-test.jsonl`, removes the folder only if it holds no junction |
| Access check | `backup.py access-check`; also inside every restore test and every run | as the running account: append to, delete and rename a snapshot (`CANARY.txt`), delete the mirror ref `refs/canary/backup` by push and by direct edit, lift the deny ACE. All must be refused; anything that gets through is put back and reported. With one account for agents and backups, the last two get through (HQ/handoffs/backup BKP-1, HANDOFF §5) |
| Dashboard | `Toolchain/dashboard/build.py` `backup()` | four lines: recovery point objective (minutes of work at risk, target 30), coverage, latest recovery point, restore test + access check |

## Rules

- Agents never write under `E:\backups` except through the mirror push. `install.ps1`, `backup.py run`,
  `snapshot` and `prune` are for the scheduled task, Rex, or the backup keeper.
- Never `rm -rf`/`Remove-Item -Recurse` anything under `E:\backups`; the denies will stop it part-way.
- The deny ACEs stop accidental and junction-following deletes (I-1048). They do not stop a deliberate same-user
  attacker (the owner can rewrite the ACL); a second account or another drive would (BKP issues).
- I-1048's junction rule stays; this does not replace it.

## Commands

    python backup.py status                  # JSON the dashboard reads
    python backup.py mirror --repo kernel    # push one repo (needs its mirror)
    python backup.py access-check            # the tamper attempts, as this account
    python backup.py prune --dry             # what retention would remove
    python test_backup.py                    # 7 tests on a throwaway root
    .\install.ps1 -CopyOnly                  # refresh the protected copy after editing backup.py or config.json
