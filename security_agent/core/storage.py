"""Single writer, durable checkpoints and content integrity."""
import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=True, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


@contextmanager
def lock(root):
    with (Path(root) / ".lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("run already has an active writer") from exc
        yield


def seal(root, relative):
    return {"path": relative, "sha256": digest((Path(root) / relative).read_bytes())}


def verify(root, record):
    path = Path(root) / record["path"]
    if not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError("artifact path escapes run")
    if digest(path.read_bytes()) != record["sha256"]:
        raise ValueError(f"artifact changed: {record['path']}")
