"""Cutover package exporter. Stdlib only. No live effects.

Exports scripts/stock_cutover/*.py verbatim into a user-owned scratch dir
with no .git, plus MANIFEST recording exact source hashes and expected
root-owned install modes under /var/lib/hermes-stock-activation/recovery.
MANIFEST is UNSIGNED (signed=false). Parent verifies REVIEWED digests
after root-owned install. Retention: journal and rollback bytes never
deleted by this package.
"""

import ast
import hashlib
import json
import os
import stat

INSTALL_PREFIX = "/var/lib/hermes-stock-activation/recovery"
RECOVERY_DIR_MODE = 0o500
ENTRY_REL = "cutover"
ENTRY_MODE = 0o500
MANIFEST_REL = "MANIFEST.json"
MANIFEST_MODE = 0o400
README_REL = "README.parent.md"
README_MODE = 0o400

PACKAGE_FILES = (
    "__init__.py",
    "cutover_units.py",
    "cutover_host.py",
    "cutover_orchestrate.py",
    "cutover_recovery.py",
    "cli.py",
)

_ALLOWED_TOP = frozenset({
    "hashlib", "json", "os", "stat", "subprocess", "sys",
    "socket", "time", "re", "urllib", "http", "importlib",
    "fcntl", "base64",
})
_ALLOWED_FROM_ROOT = frozenset({"urllib", "http"})

_DENIED_COMPONENTS = frozenset({
    ".git", ".env", ".envrc", "__pycache__", ".leases",
    "state.db", "state.db-wal", "state.db-shm",
})

_LIVE_PREFIXES = (
    "/var/lib/hermes-stock-activation",
    "/run/hermes-stock-activation",
    "/etc/systemd",
    "/opt",
    "/home/ubuntu/.hermes",
)


def _is_under(path, prefix):
    if path == prefix:
        return True
    return path.startswith(prefix + "/")


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _source_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return here


def _check_dest(dest_dir):
    if not isinstance(dest_dir, str) or not dest_dir:
        raise ValueError("dest type")
    if isinstance(dest_dir, bool):
        raise ValueError("dest bool")
    if not os.path.isabs(dest_dir):
        raise ValueError("dest not absolute")
    norm = os.path.normpath(dest_dir)
    if norm.startswith("/tmp/") or norm == "/tmp":
        raise ValueError("dest must not be /tmp (use home scratch TMPDIR)")
    for prefix in ("/var", "/run", "/etc", "/opt"):
        if norm == prefix or norm.startswith(prefix + "/"):
            raise ValueError("dest protected")
    for prefix in _LIVE_PREFIXES:
        if norm == prefix or _is_under(norm, prefix):
            raise ValueError("dest live")
    home = os.path.expanduser("~")
    if home and os.path.isabs(home):
        hnorm = os.path.normpath(home)
        if norm != hnorm and not norm.startswith(hnorm + "/"):
            raise ValueError("dest must be under HOME scratch")
    for comp in norm.split("/"):
        if comp in _DENIED_COMPONENTS or comp.endswith(".pyc"):
            raise ValueError("dest denied component")
        if comp == ".git":
            raise ValueError("dest .git")
    return norm


def _verify_closure_bytes(data, rel):
    try:
        text = data.decode("utf-8")
    except Exception:
        raise ValueError("source not utf-8: " + rel)
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root not in _ALLOWED_TOP:
                    raise ValueError(f"forbidden import {a.name} in {rel}")
                if root == "scripts":
                    raise ValueError(f"user path import in {rel}")
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                raise ValueError(f"relative import refused in {rel}")
            root = node.module.split(".")[0]
            if root not in _ALLOWED_TOP:
                raise ValueError(f"forbidden from-import {node.module} in {rel}")
    if "import scripts" in text or "from scripts" in text:
        raise ValueError(f"user path import text in {rel}")
    # No arbitrary PID termination primitives as code (string literals used
    # for unit-text validation are allowed; attribute/call use is not).
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr in ("kill", "killpg", "terminate"):
                raise ValueError(f"termination primitive in {rel}: {node.attr}")
        if isinstance(node, ast.Name):
            if node.id in ("killpg", "SIGKILL", "SIGTERM"):
                # Bare names that resolve to termination; string literals
                # with the same characters are Constant, not Name.
                raise ValueError(f"termination name in {rel}: {node.id}")
    # Forbid signal module import as code (validation strings may mention
    # KillSignal as unit-text checks; those are Constant, not Import).
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] == "signal":
                    raise ValueError(f"signal import in {rel}")
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "signal":
                raise ValueError(f"signal import in {rel}")
    # Must not open live secrets path as read target (refusal string ok).
    if ".hermes/.env" in text:
        # Allow only the refusal constant definition, not open().
        if "open(" in text and ".env" in text:
            # Check if it's the ENV_FILE_PATH constant (allowed as constant)
            # versus an actual open of .env. Refuse any open containing .env.
            for line in text.splitlines():
                if "open(" in line and ".env" in line:
                    raise ValueError(f"live .env open in {rel}")
    return True


def _parent_readme_text(entry_shas, manifest_sha):
    lines = []
    lines.append("# Parent (root) cutover install — separate from operator proof")
    lines.append("")
    lines.append("This package is UNSIGNED (signed=false). MANIFEST self-hash")
    lines.append("provides NO trust. Parent must verify REVIEWED digests after")
    lines.append("root-owned install, before any execution.")
    lines.append("")
    lines.append("Reviewed source digests (pinned by independent review):")
    for rel, sha in sorted(entry_shas.items()):
        lines.append(f"- {rel} sha256={sha}")
    lines.append(f"- MANIFEST.json sha256={manifest_sha} (self-hash, NOT trust)")
    lines.append("")
    lines.append("Expected root-owned install layout:")
    lines.append(f"- {INSTALL_PREFIX} dir mode 0500 uid 0 gid 0")
    for rel in PACKAGE_FILES:
        if rel == "__init__.py":
            continue
        lines.append(f"- {INSTALL_PREFIX}/{rel} mode 0500 uid 0 gid 0 "
                     "or cutover entry mode 0500")
    lines.append(f"- {INSTALL_PREFIX}/{MANIFEST_REL} mode 0400 uid 0 gid 0")
    lines.append(f"- {INSTALL_PREFIX}/{README_REL} mode 0400 uid 0 gid 0")
    lines.append("")
    lines.append("## 1. Verify export (as user, no root, no sudo)")
    lines.append("")
    lines.append("Export dir <EXPORT> contains no .git. Verify:")
    lines.append("  test ! -e <EXPORT>/.git")
    lines.append("  /usr/bin/python3 -I <EXPORT>/cli.py plan  # manifest-ready, exit 0")
    lines.append("")
    lines.append("## 2. Install (as root parent only — DO NOT run as user)")
    lines.append("")
    lines.append(f"  /usr/bin/install -d -o 0 -g 0 -m 0500 {INSTALL_PREFIX}")
    for rel in PACKAGE_FILES:
        if rel == "__init__.py":
            continue
        lines.append(f"  /usr/bin/install -o 0 -g 0 -m 0500 <EXPORT>/{rel} {INSTALL_PREFIX}/{rel}")
    lines.append(f"  /usr/bin/install -o 0 -g 0 -m 0400 <EXPORT>/{MANIFEST_REL} {INSTALL_PREFIX}/{MANIFEST_REL}")
    lines.append(f"  /usr/bin/install -o 0 -g 0 -m 0400 <EXPORT>/{README_REL} {INSTALL_PREFIX}/{README_REL}")
    lines.append("")
    lines.append("Then verify root-owned digests equal REVIEWED values.")
    lines.append("")
    lines.append("## 3. Cutover plan (as root, no live effects; deterministic)")
    lines.append("")
    lines.append(f"  /usr/bin/python3 -I {INSTALL_PREFIX}/cli.py plan")
    lines.append("")
    lines.append("Expected: status manifest-ready, signed false, activation UNEXECUTED,")
    lines.append("service_cutover NOT-AUTHORIZED (no receipt; parent review required).")
    lines.append("Preflight (read-only, verifies siblings before import):")
    lines.append("  /usr/bin/python3 -I <EXPORT>/cli.py preflight  # exit 0, no mutation")
    lines.append(f"  /usr/bin/python3 -I {INSTALL_PREFIX}/cli.py preflight")
    lines.append("")
    lines.append("Refusal check (must exit 3 without --execute-live, no live effects):")
    lines.append(f"  /usr/bin/python3 -I {INSTALL_PREFIX}/cli.py apply; echo $?  # must print 3")
    lines.append("")
    lines.append("Live apply requires --execute-live as root from installed path")
    lines.append("after digest verification. This document does not authorize live.")
    lines.append("Retention: journal and rollback bytes never deleted; OnFailure")
    lines.append("recovery re-enters fence, never second start while ambiguous.")
    lines.append("")
    return "\n".join(lines) + "\n"


def _readme_template_hash():
    probe = _parent_readme_text({"cli.py": "ENTRY_SHA_PLACEHOLDER"}, "MANIFEST_SHA_PLACEHOLDER")
    return _sha256_bytes(probe.encode("utf-8"))


def export_cutover_package(dest_dir):
    norm = _check_dest(dest_dir)
    src_dir = _source_dir()
    entry_shas = {}
    payloads = {}
    for rel in PACKAGE_FILES:
        src = os.path.join(src_dir, rel)
        with open(src, "rb") as f:
            data = f.read()
        _verify_closure_bytes(data, rel)
        entry_shas[rel] = _sha256_bytes(data)
        payloads[rel] = data
    template_sha = _readme_template_hash()
    if os.path.lexists(norm):
        st = os.lstat(norm)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("dest not dir")
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("dest symlink")
    else:
        os.makedirs(norm, mode=0o700, exist_ok=False)
    if os.path.lexists(os.path.join(norm, ".git")):
        raise ValueError("export has .git")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    for rel, data in payloads.items():
        # cli.py is the public entry; keep name cli.py (parent installs as cutover entry too).
        p = os.path.join(norm, rel)
        if os.path.lexists(p):
            raise ValueError("export exists: " + rel)
        fd = os.open(p, flags, 0o600)
        try:
            off = 0
            view = bytes(data)
            while off < len(view):
                n = os.write(fd, view[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    manifest_entries = []
    for rel in sorted(entry_shas.keys()):
        mode_str = format(0o500 if rel != MANIFEST_REL else 0o400, "04o")
        manifest_entries.append((rel, "file", mode_str, entry_shas[rel], "-"))
    manifest_entries.sort(key=lambda e: e[0])
    manifest_lines = [f"{rel} {typ} {mode} {sha} {tgt}" for rel, typ, mode, sha, tgt in manifest_entries]
    manifest_text = "\n".join(manifest_lines) + "\n"
    manifest_sha = _sha256_bytes(manifest_text.encode("utf-8"))
    readme_text = _parent_readme_text(entry_shas, manifest_sha)
    readme_sha = _sha256_bytes(readme_text.encode("utf-8"))
    payload = {
        "format": 1,
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "NOT-AUTHORIZED",
        "install_prefix": INSTALL_PREFIX,
        "expected_dir_mode": format(RECOVERY_DIR_MODE, "04o"),
        "expected_uid": 0,
        "expected_gid": 0,
        "files": [
            {"rel": rel, "type": "file",
             "mode": format(0o500, "04o"),
             "sha256": entry_shas[rel], "target": "-"}
            for rel in sorted(entry_shas.keys())
        ],
        "manifest": manifest_text,
        "manifest_sha256": manifest_sha,
        "readme_sha256": readme_sha,
        "template_sha256": template_sha,
        "kernel_immutable": False,
        "live_published": False,
        "retention": "journal and rollback bytes never deleted",
    }
    for rel, text in ((README_REL, readme_text),):
        p = os.path.join(norm, rel)
        if os.path.lexists(p):
            raise ValueError("export exists: " + rel)
        f2 = os.open(p, flags, 0o600)
        try:
            b = text.encode("utf-8")
            off = 0
            while off < len(b):
                n = os.write(f2, b[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
            os.fsync(f2)
        finally:
            os.close(f2)
    man_path = os.path.join(norm, MANIFEST_REL)
    if os.path.lexists(man_path):
        raise ValueError("export exists: manifest")
    man_bytes = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    f3 = os.open(man_path, flags, 0o600)
    try:
        off = 0
        while off < len(man_bytes):
            n = os.write(f3, man_bytes[off:])
            if n == 0:
                raise OSError("short write")
            off += n
        os.fsync(f3)
    finally:
        os.close(f3)
    dfd = os.open(norm, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return {
        "status": "cutover-exported",
        "success": True,
        "dest_dir": norm,
        "entry_shas": entry_shas,
        "manifest": manifest_text,
        "manifest_sha256": manifest_sha,
        "manifest_path": man_path,
        "readme_path": os.path.join(norm, README_REL),
        "readme_sha256": readme_sha,
        "template_sha256": template_sha,
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "NOT-AUTHORIZED",
        "install_prefix": INSTALL_PREFIX,
    }


def main(argv=None):
    import sys as _sys
    if argv is None:
        argv = _sys.argv[1:]
    if len(argv) != 2 or argv[0] != "export":
        print("usage: cutover_package export <dest_dir>", file=_sys.stderr)
        return 2
    try:
        res = export_cutover_package(argv[1])
    except (ValueError, OSError) as e:
        print(f"export-refused: {e}", file=_sys.stderr)
        return 1
    print(json.dumps(res, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
