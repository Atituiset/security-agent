"""Read commits through Git plumbing; never check out or execute target code."""
import subprocess
import os
from pathlib import Path
from security_agent.core.storage import digest, seal

EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc"}


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=30,
                            env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"})
    if result.returncode:
        raise ValueError(result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def resolve(repo, revision):
    return git(repo, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()


def snapshot(repo, base_ref, head_ref, root, max_bytes):
    repo = str(Path(git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve())
    base, head = resolve(repo, base_ref), resolve(repo, head_ref)
    tree = git(repo, "ls-tree", "-rz", "--full-tree", head)
    diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", base, head, "--")
    (root / "diff.patch").write_bytes(diff)
    (root / "tree.raw").write_bytes(tree)
    changed = set(git(repo, "diff", "--name-only", "-z", "--no-renames", base, head, "--").split(b"\0"))
    sources, targets, excluded = {}, [], []
    entries = []
    total = 0
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        meta, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        path = raw_path.decode("utf-8")
        if Path(path).suffix.lower() not in EXTENSIONS:
            continue
        if raw_path in changed:
            targets.append(path)
        if mode not in ("100644", "100755") or kind != "blob":
            excluded.append(f"unsupported source mode: {path}")
            continue
        size = int(git(repo, "cat-file", "-s", oid))
        total += size
        entries.append((path, oid))
    # Fail closed for the whole source view, rather than pretending truncated code is complete.
    if total > max_bytes:
        excluded.append(f"source context {total} bytes exceeds limit {max_bytes}")
    if not excluded:
        for path, oid in entries:
            data = git(repo, "cat-file", "blob", oid)
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                excluded.append(f"non-UTF-8 source: {path}")
                continue
            sha = digest(data)
            rel = "snapshots/" + sha
            (root / rel).write_bytes(data)
            sources[path] = {"blob": oid, **seal(root, rel)}
    return {"repo": repo, "base_ref": base_ref, "head_ref": head_ref,
            "base": base, "head": head, "sources": sources,
            "artifacts": [seal(root, "diff.patch"), seal(root, "tree.raw")],
            "targets": sorted(targets), "limitations": excluded,
            "context_bytes": total, "scope": "commit-only; changed files, not only added lines"}


def source_view(root, baseline):
    return {path: (root / record["path"]).read_bytes().decode("utf-8")
            for path, record in baseline["sources"].items()}


def check_baseline(root, state):
    from security_agent.core.storage import verify
    baseline = state["baseline"]
    for label in ("base", "head"):
        if resolve(baseline["repo"], baseline[label + "_ref"]) != baseline[label]:
            raise ValueError(f"{label} reference moved; create a new run")
    for record in baseline["artifacts"] + list(baseline["sources"].values()):
        verify(root, record)
    for attempt in state["attempts"]:
        for record in attempt.get("artifacts", []):
            verify(root, record)
    for unit in state["investigations"]:
        for key in ("assessment_artifact", "decision_artifact"):
            if unit.get(key):
                verify(root, unit[key])
