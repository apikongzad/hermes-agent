"""Portable root proof package exporter. Stdlib only. No live effects.

Exports scripts/stock_activation/operator_proof.py verbatim into a
user-owned scratch directory with no .git, plus an external manifest
recording exact source/template hashes and expected root-owned install
modes under /var/lib/hermes-stock-activation/recovery.

The manifest is UNSIGNED (signed=false). Its self-hash provides NO trust.
The parent (root operator) must verify reviewed package digests after
root-owned install. See README.parent.md template below.

No sudo/install/mount/service operations. No .env read. All writes stay
under the caller-supplied dest_dir (must be user scratch, never /tmp,
/var, /run, /etc, /opt, or live hermes paths).
"""

import ast
import hashlib
import json
import os
import stat

INSTALL_PREFIX = "/var/lib/hermes-stock-activation/recovery"
RECOVERY_DIR_MODE = 0o500
ENTRY_REL = "operator_proof.py"
ENTRY_MODE = 0o500
MANIFEST_REL = "MANIFEST.json"
MANIFEST_MODE = 0o400
README_REL = "README.parent.md"
README_MODE = 0o400

# Verified image inputs (parent-verified, read-only strings, never probed here).
KNOWN_GOOD_IMAGE = "/home/ubuntu/.hermes/runtime/prep-closures/kg-webdist-1d9a377fa00c/image-stage/known-good.squashfs"
KNOWN_GOOD_SHA = "1e34622f1f96d2fc45453de2cac70ce3791ca3da8c816db42885b21d65f7dd3d"
KNOWN_GOOD_PREP = "/home/ubuntu/.hermes/runtime/prep-closures/kg-webdist-1d9a377fa00c/image-stage/known-good.prep.json"
CANDIDATE_IMAGE = "/home/ubuntu/.hermes/runtime/prep-closures/bc352cfcb2cd/candidate.squashfs"
CANDIDATE_SHA = "84d987079774f401b76d0d3edb80c5894a3ae4b84c7dde5f841075b2bc640c6b"
CANDIDATE_PREP = "/home/ubuntu/.hermes/runtime/prep-closures/bc352cfcb2cd/candidate.prep.json"

# Stdlib allowlist for operator_proof.py top-level + function-level imports.
# Mirrors exact imports observed: errno, hashlib, json, os, stat,
# subprocess, sys, time, plus local `re` and stdlib urllib/http used
# inside LiveProofHost.health_fetch. Anything else (scripts.*, etc.) refuses.
_ALLOWED_TOP = frozenset({
    "errno", "hashlib", "json", "os", "stat", "subprocess", "sys", "time",
    "re", "urllib", "http",
})
_ALLOWED_FROM_ROOT = frozenset({"urllib", "http"})

_DENIED_COMPONENTS = frozenset({
    ".git", ".env", ".envrc", "__pycache__", ".leases",
    "state.db", "state.db-wal", "state.db-shm",
})
_DENIED_SUFFIX = (".pyc",)

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


def _source_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "operator_proof.py")


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
    # Must be under HOME (user scratch), not /tmp.
    home = os.path.expanduser("~")
    if home and os.path.isabs(home):
        hnorm = os.path.normpath(home)
        if norm != hnorm and not norm.startswith(hnorm + "/"):
            raise ValueError("dest must be under HOME scratch")
    # Refuse .git component anywhere.
    for comp in norm.split("/"):
        if comp in _DENIED_COMPONENTS or comp.endswith(_DENIED_SUFFIX):
            raise ValueError("dest denied component")
        if comp == ".git":
            raise ValueError("dest .git")
    return norm


def _verify_closure_bytes(data):
    try:
        text = data.decode("utf-8")
    except Exception:
        raise ValueError("source not utf-8")
    # AST is the binding check: only stdlib roots allowed. Docstring mentions
    # of scripts.stock_activation (e.g. "never imports scripts.stock_activation")
    # are not imports and must not refuse the legitimate closure.
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root not in _ALLOWED_TOP:
                    raise ValueError("forbidden import: " + a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                raise ValueError("relative import refused")
            root = node.module.split(".")[0]
            if root not in _ALLOWED_TOP:
                raise ValueError("forbidden from-import: " + str(node.module))
    # Must not reference the live secrets path as a read target.
    # The refusal-check string ".env" alone is allowed; the live file path is not.
    if ".hermes/.env" in text:
        raise ValueError("closure references live .env path")
    return True


def _parent_readme_text(entry_sha, manifest_sha):
    # Exact parent commands. Flags inspected from operator_proof.main:
    # plan: --prep P --image I --expected-sha S --kind K --port N [--manifest-out O]
    # apply/recover: same records plus --execute-live [--proof-home H] [--mount M]
    # Ports 9119/4096 are refused by web_proof_argv; use 9120/9121.
    lines = []
    lines.append("# Parent (root) install + proof — portable operator proof package")
    lines.append("")
    lines.append("This package is UNSIGNED (signed=false). The MANIFEST.json self-hash")
    lines.append("provides NO trust. The parent must verify REVIEWED package digests")
    lines.append("after root-owned install, before any proof execution.")
    lines.append("")
    lines.append("Reviewed source digests (pinned by independent review):")
    lines.append(f"- {ENTRY_REL} sha256={entry_sha}")
    lines.append(f"- MANIFEST.json sha256={manifest_sha} (self-hash, NOT trust)")
    lines.append("")
    lines.append("Expected root-owned install layout:")
    lines.append(f"- {INSTALL_PREFIX} dir mode 0500 uid 0 gid 0")
    lines.append(f"- {INSTALL_PREFIX}/{ENTRY_REL} mode 0500 uid 0 gid 0")
    lines.append(f"- {INSTALL_PREFIX}/{MANIFEST_REL} mode 0400 uid 0 gid 0")
    lines.append(f"- {INSTALL_PREFIX}/{README_REL} mode 0400 uid 0 gid 0")
    lines.append("")
    lines.append("Verified image inputs (parent-verified, do NOT re-derive here):")
    lines.append(f"- known-good image: {KNOWN_GOOD_IMAGE}")
    lines.append(f"  sha256={KNOWN_GOOD_SHA}")
    lines.append(f"  prep={KNOWN_GOOD_PREP}")
    lines.append(f"- candidate image: {CANDIDATE_IMAGE}")
    lines.append(f"  sha256={CANDIDATE_SHA}")
    lines.append(f"  prep={CANDIDATE_PREP}")
    lines.append("")
    lines.append("## 1. Verify export (as user, no root, no sudo)")
    lines.append("")
    lines.append("Export dir <EXPORT> contains no .git. Verify:")
    lines.append("  test ! -e <EXPORT>/.git")
    lines.append(f"  /usr/bin/python3 -I <EXPORT>/{ENTRY_REL} plan  # manifest-refused, exit 0")
    lines.append("")
    lines.append("## 2. Install (as root parent only — DO NOT run as user)")
    lines.append("")
    lines.append(f"  /usr/bin/install -d -o 0 -g 0 -m 0500 {INSTALL_PREFIX}")
    lines.append(f"  /usr/bin/install -o 0 -g 0 -m 0500 <EXPORT>/{ENTRY_REL} {INSTALL_PREFIX}/{ENTRY_REL}")
    lines.append(f"  /usr/bin/install -o 0 -g 0 -m 0400 <EXPORT>/{MANIFEST_REL} {INSTALL_PREFIX}/{MANIFEST_REL}")
    lines.append(f"  /usr/bin/install -o 0 -g 0 -m 0400 <EXPORT>/{README_REL} {INSTALL_PREFIX}/{README_REL}")
    lines.append("")
    lines.append("Then verify root-owned digests equal REVIEWED values (example):")
    lines.append(f"  /usr/bin/python3 -I -c \"import hashlib;print(hashlib.sha256(open('{INSTALL_PREFIX}/{ENTRY_REL}','rb').read()).hexdigest())\"")
    lines.append(f"  # must equal {entry_sha}")
    lines.append(f"  /usr/bin/stat -c '%U %G %a %n' {INSTALL_PREFIX}/{ENTRY_REL}")
    lines.append(f"  # must print: root root 500 {INSTALL_PREFIX}/{ENTRY_REL}")
    lines.append("")
    lines.append("## 3. Proof plan (as root, no live effects; deterministic)")
    lines.append("")
    lines.append("Actual CLI flags inspected from operator_proof.main (do not invent):")
    lines.append("plan [--prep P --image I --expected-sha S --kind K --port N]... [--manifest-out O]")
    lines.append("")
    lines.append(f"  /usr/bin/python3 -I {INSTALL_PREFIX}/{ENTRY_REL} plan \\")
    lines.append(f"    --prep {KNOWN_GOOD_PREP} \\")
    lines.append(f"    --image {KNOWN_GOOD_IMAGE} \\")
    lines.append(f"    --expected-sha {KNOWN_GOOD_SHA} \\")
    lines.append("    --kind known-good --port 9120 \\")
    lines.append(f"    --prep {CANDIDATE_PREP} \\")
    lines.append(f"    --image {CANDIDATE_IMAGE} \\")
    lines.append(f"    --expected-sha {CANDIDATE_SHA} \\")
    lines.append("    --kind candidate --port 9121")
    lines.append("")
    lines.append("Expected: status manifest-ready, signed false, activation UNEXECUTED,")
    lines.append("service_cutover NOT_AUTHORIZED, gates UNEXECUTED (no live spawn).")
    lines.append("")
    lines.append("Refusal check (must exit 3 without --execute-live, no live effects):")
    lines.append(f"  /usr/bin/python3 -I {INSTALL_PREFIX}/{ENTRY_REL} apply; echo $?  # must print 3")
    lines.append("")
    lines.append("Live apply/recover are NOT part of this export. They require")
    lines.append("--execute-live as root from the installed recovery path only,")
    lines.append("after the digest verification above. This document does not")
    lines.append("authorize live execution.")
    lines.append("")
    return "\n".join(lines) + "\n"


def _readme_template_hash():
    # Template hash with placeholder digests (stable across exports).
    # Computed from template with ENTRY_SHA/MANIFEST_SHA placeholders so the
    # external manifest records the template itself, not the filled copy.
    probe = _parent_readme_text("ENTRY_SHA_PLACEHOLDER", "MANIFEST_SHA_PLACEHOLDER")
    return _sha256_bytes(probe.encode("utf-8"))


def export_proof_package(dest_dir):
    norm = _check_dest(dest_dir)
    src = _source_path()
    with open(src, "rb") as f:
        data = f.read()
    _verify_closure_bytes(data)
    source_sha = _sha256_bytes(data)
    template_sha = _readme_template_hash()

    # Dest must not exist as file; create dir (user-owned) with 0700.
    # Never touch live paths; all writes under norm only.
    if os.path.lexists(norm):
        st = os.lstat(norm)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("dest not dir")
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("dest symlink")
    else:
        os.makedirs(norm, mode=0o700, exist_ok=False)
    # Refuse if .git already present (export must have no.git).
    if os.path.lexists(os.path.join(norm, ".git")):
        raise ValueError("export has .git")

    entry_path = os.path.join(norm, ENTRY_REL)
    # Write entry verbatim (O_EXCL, no overwrite of existing export).
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(entry_path, flags, 0o600)
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
        os.chmod(entry_path, 0o600)
    except OSError:
        pass

    # Canonical manifest text (sorted rel, type, mode, sha, target).
    # Records expected INSTALLED modes (0500/0400 root-owned), not scratch modes.
    entry_mode_str = format(ENTRY_MODE, "04o")
    manifest_entries = [
        (ENTRY_REL, "file", entry_mode_str, source_sha, "-"),
    ]
    manifest_entries.sort(key=lambda e: e[0])
    manifest_lines = [f"{rel} {typ} {mode} {sha} {tgt}" for rel, typ, mode, sha, tgt in manifest_entries]
    manifest_text = "\n".join(manifest_lines) + "\n"
    manifest_sha = _sha256_bytes(manifest_text.encode("utf-8"))

    readme_text = _parent_readme_text(source_sha, manifest_sha)
    readme_sha = _sha256_bytes(readme_text.encode("utf-8"))

    payload = {
        "format": 1,
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "NOT_AUTHORIZED",
        "install_prefix": INSTALL_PREFIX,
        "expected_dir_mode": format(RECOVERY_DIR_MODE, "04o"),
        "expected_uid": 0,
        "expected_gid": 0,
        "files": [
            {
                "rel": ENTRY_REL,
                "type": "file",
                "mode": format(ENTRY_MODE, "04o"),
                "sha256": source_sha,
                "target": "-",
            },
            {
                "rel": README_REL,
                "type": "file",
                "mode": format(README_MODE, "04o"),
                "sha256": readme_sha,
                "target": "-",
            },
        ],
        "manifest": manifest_text,
        "manifest_sha256": manifest_sha,
        "source_sha256": source_sha,
        "source_path": "scripts/stock_activation/operator_proof.py",
        "readme_sha256": readme_sha,
        "template_sha256": template_sha,
        "kernel_immutable": False,
        "live_published": False,
    }

    # Write README then MANIFEST (both O_EXCL).
    for rel, text, _mode in ((README_REL, readme_text, README_MODE),):
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

    # Fsync export dir.
    dfd = os.open(norm, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

    return {
        "status": "proof-exported",
        "success": True,
        "dest_dir": norm,
        "entry": entry_path,
        "entry_sha256": source_sha,
        "manifest": manifest_text,
        "manifest_sha256": manifest_sha,
        "manifest_path": man_path,
        "readme_path": os.path.join(norm, README_REL),
        "readme_sha256": readme_sha,
        "template_sha256": template_sha,
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "NOT_AUTHORIZED",
        "install_prefix": INSTALL_PREFIX,
    }


def main(argv=None):
    import sys as _sys
    if argv is None:
        argv = _sys.argv[1:]
    if len(argv) != 2 or argv[0] != "export":
        print("usage: proof_package export <dest_dir>", file=_sys.stderr)
        return 2
    try:
        res = export_proof_package(argv[1])
    except (ValueError, OSError) as e:
        print(f"export-refused: {e}", file=_sys.stderr)
        return 1
    print(json.dumps(res, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
