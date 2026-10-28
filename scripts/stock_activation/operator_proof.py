"""Runnerless operator proof. Stdlib only. No live effects unless --execute-live.

Live execution never imports scripts.stock_activation.
"""

import errno
import hashlib
import json
import os
import stat
import subprocess
import sys

PROOF_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}

LIB_DIR = "/var/lib/hermes-stock-activation"
BACKING_DIR = "/var/lib/hermes-stock-activation/backing"
RUN_DIR = "/run/hermes-stock-activation"

KNOWN_GOOD_DEST = "/var/lib/hermes-stock-activation/backing/known-good.squashfs"
KNOWN_GOOD_MOUNT = "/run/hermes-stock-activation/known-good-snap"
KNOWN_GOOD_DIGEST = "/var/lib/hermes-stock-activation/digest-known-good"
CANDIDATE_DEST = "/var/lib/hermes-stock-activation/backing/candidate.squashfs"
CANDIDATE_MOUNT = "/run/hermes-stock-activation/candidate-snap"
CANDIDATE_DIGEST = "/var/lib/hermes-stock-activation/digest-candidate"

RECOVERY_PREFIX = "/var/lib/hermes-stock-activation/recovery"

_DENIED_EXACT = frozenset({
    ".git",
    ".env",
    ".envrc",
    "__pycache__",
    ".leases",
    "state.db",
    "state.db-wal",
    "state.db-shm",
})

_GATES = ("A1", "C2", "CLI_PROOF", "WEB_PROOF", "MOUNT", "PROVISION", "DIGEST")

_FORBIDDEN_MANIFEST_OUT = (
    "/var/lib",
    "/run",
    "/etc",
    "/opt",
    "/home/ubuntu/.hermes",
)


def file_uid_of(path):
    if isinstance(path, bool):
        raise TypeError("bool path refused")
    st = os.lstat(path)
    return st.st_uid


def _lstat_uid_gid(path):
    if isinstance(path, bool):
        raise TypeError("bool path refused")
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None, None
    except OSError:
        return None, None
    try:
        return st.st_uid, st.st_gid
    except Exception:
        return None, None


def _is_denied_rel(rel):
    parts = rel.split("/")
    for comp in parts:
        if comp in _DENIED_EXACT:
            return True
        if comp.endswith(".pyc"):
            return True
    if rel.endswith(".pyc"):
        return True
    return False


def _parse_manifest_lines(text):
    entries = []
    if text is None:
        return entries
    if not isinstance(text, str):
        return entries
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) == 5:
            rel, typ, mode, sha, target = parts
        elif len(parts) == 4:
            rel, typ, sha, target = parts
            mode = "-"
        else:
            continue
        entries.append({
            "rel": rel,
            "type": typ,
            "mode": mode,
            "sha": sha,
            "target": target,
        })
    return entries


def inventory_closure(prep_path, image_path=None):
    base = {
        "copied": 0,
        "git_invoked": False,
        "signed": False,
    }
    try:
        with open(prep_path, "rb") as f:
            payload = json.loads(f.read().decode("utf-8"))
    except Exception as e:
        return {
            **base,
            "status": "inventory-refused",
            "denylist_hits": [],
            "hits": [],
            "counts": {"source": 0, "venv": 0, "interpreter": 0, "deps": 0},
            "venv_python_targets": {},
            "venv_python_symlink_targets": {},
            "interpreter_file_count": 0,
            "interpreter_regular_file_count": 0,
            "web_dist": None,
            "source_sha": None,
            "image_sha256": None,
            "image_bytes": None,
            "manifest_sha256": None,
            "file_uid": None,
            "file_gid": None,
            "image_uid": None,
            "image_gid": None,
            "prep_path": prep_path,
            "image_path": image_path,
            "error": str(e),
        }
    manifest_text = payload.get("manifest", "")
    entries = _parse_manifest_lines(manifest_text)
    counts = {"source": 0, "venv": 0, "interpreter": 0, "deps": 0}
    for e in entries:
        top = e["rel"].split("/")[0] if "/" in e["rel"] else e["rel"]
        if top in counts:
            counts[top] += 1
    hits = sorted([e["rel"] for e in entries if _is_denied_rel(e["rel"])])
    venv_targets = {}
    for e in entries:
        rel = e["rel"]
        if e["type"] != "symlink":
            continue
        if not rel.startswith("venv/bin/"):
            continue
        name = rel.rsplit("/", 1)[-1]
        if name in ("python", "python3", "python3.14"):
            venv_targets[rel] = e["target"]
    interp_count = sum(
        1 for e in entries
        if (e["rel"] == "interpreter" or e["rel"].startswith("interpreter/"))
        and e["type"] == "file"
    )
    prep_uid, prep_gid = _lstat_uid_gid(prep_path)
    # image path for uid: explicit arg else payload image_path if it exists
    img_for_stat = image_path if image_path is not None else payload.get("image_path")
    if img_for_stat is None:
        img_uid, img_gid = None, None
    else:
        try:
            img_uid, img_gid = _lstat_uid_gid(img_for_stat)
        except TypeError:
            raise
        except Exception:
            img_uid, img_gid = None, None
    # file_uid_of must be used for prep uid path (validates bool rejection)
    # Re-derive prep uid via file_uid_of when file exists to satisfy contract.
    if prep_uid is not None:
        try:
            prep_uid_checked = file_uid_of(prep_path)
            prep_uid = prep_uid_checked
        except Exception:
            pass
    echoed = {
        "web_dist": payload.get("web_dist"),
        "source_sha": payload.get("source_sha"),
        "image_sha256": payload.get("image_sha256"),
        "image_bytes": payload.get("image_bytes"),
        "manifest_sha256": payload.get("manifest_sha256"),
    }
    if hits:
        return {
            **base,
            "status": "inventory-refused",
            "denylist_hits": hits,
            "hits": hits,
            "counts": counts,
            "venv_python_targets": dict(venv_targets),
            "venv_python_symlink_targets": dict(venv_targets),
            "interpreter_file_count": interp_count,
            "interpreter_regular_file_count": interp_count,
            "file_uid": prep_uid,
            "file_gid": prep_gid,
            "image_uid": img_uid,
            "image_gid": img_gid,
            "prep_path": prep_path,
            "image_path": image_path,
            **echoed,
        }
    return {
        **base,
        "status": "inventoried",
        "denylist_hits": [],
        "hits": [],
        "counts": counts,
        "venv_python_targets": dict(venv_targets),
        "venv_python_symlink_targets": dict(venv_targets),
        "interpreter_file_count": interp_count,
        "interpreter_regular_file_count": interp_count,
        "file_uid": prep_uid,
        "file_gid": prep_gid,
        "image_uid": img_uid,
        "image_gid": img_gid,
        "prep_path": prep_path,
        "image_path": image_path,
        **echoed,
    }


def losetup_argv(image):
    return ["/usr/sbin/losetup", "--find", "--show", "--read-only", "--nooverlap", "--", image]


def mount_argv(loop, mp):
    return ["/usr/bin/mount", "-n", "-t", "squashfs", "-o", "ro,nosuid,nodev", loop, mp]


def findmnt_argv(mp):
    return ["/usr/bin/findmnt", "-n", "-o", "FSTYPE,OPTIONS,SOURCE,TARGET", "--target", mp]


def umount_argv(mp):
    return ["/usr/bin/umount", "--", mp]


def losetup_detach_argv(loop):
    return ["/usr/sbin/losetup", "-d", loop]


def install_dir_argv(path, mode):
    return ["/usr/bin/install", "-d", "-o", "0", "-g", "0", "-m", mode, path]


def cli_proof_argv(mount, flag):
    return [f"{mount}/venv/bin/python3", "-I", f"{mount}/source/hermes_cli/main.py", flag]


def web_proof_argv(mount, port):
    try:
        p = int(port)
    except Exception:
        raise ValueError("bad port")
    if p in (9119, 4096):
        raise ValueError("refused port")
    return [
        f"{mount}/venv/bin/python3",
        "-I",
        f"{mount}/source/hermes_cli/main.py",
        "dashboard",
        "--isolated",
        "--skip-build",
        "--no-open",
        "--host",
        "127.0.0.1",
        "--port",
        str(p),
    ]


def losetup_list_argv(loopdev):
    return ["/usr/sbin/losetup", "--list", "--noheadings", "-O", "RO,BACK-FILE", "--", loopdev]


def _dashboard_url(port):
    try:
        p = int(port)
    except Exception:
        raise ValueError("bad port")
    if p in (9119, 4096):
        raise ValueError("refused port")
    return f"http://127.0.0.1:{p}/api/health"


def _health_ok(status, content_type, body):
    if status != 200:
        return False
    ctype = (content_type or "")
    if not isinstance(ctype, str):
        try:
            ctype = str(ctype)
        except Exception:
            return False
    if "application/json" not in ctype.lower():
        return False
    b = body
    if isinstance(b, (bytes, str)):
        try:
            if isinstance(b, bytes):
                b = b.decode("utf-8", "replace")
            b = json.loads(b)
        except Exception:
            return False
    if not isinstance(b, dict):
        return False
    return b.get("ok") is True


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _dest_for_kind(kind):
    if kind == "known-good":
        return KNOWN_GOOD_DEST, KNOWN_GOOD_MOUNT, KNOWN_GOOD_DIGEST
    if kind == "candidate":
        return CANDIDATE_DEST, CANDIDATE_MOUNT, CANDIDATE_DIGEST
    return None, None, None


def _gates_unexecuted():
    return {k: "UNEXECUTED" for k in _GATES}


def _gates_from_evidence(evidence):
    gates = _gates_unexecuted()
    if not isinstance(evidence, dict):
        return gates
    if evidence.get("executed") is not True:
        return gates
    required = ("write_errno", "rename_errno", "link_errno", "backing_writable_by_1001")
    for k in required:
        if k not in evidence:
            return gates
    # Caller-supplied evidence may only mark A1/C2, and only for EROFS + not writable.
    # It must never mark CLI_PROOF, WEB_PROOF, MOUNT, PROVISION, or DIGEST.
    if not _immutable_from_evidence(evidence):
        return gates
    gates["A1"] = "EXECUTED"
    gates["C2"] = "EXECUTED"
    return gates


def _evidence_for_kind(record_evidence, global_evidence, kind):
    if isinstance(record_evidence, dict):
        return record_evidence
    if isinstance(global_evidence, dict):
        # global may be per-kind mapping or single evidence
        if kind in global_evidence and isinstance(global_evidence[kind], dict):
            return global_evidence[kind]
        if "executed" in global_evidence:
            return global_evidence
    return None


def _immutable_from_evidence(ev):
    if not isinstance(ev, dict):
        return False
    if ev.get("executed") is not True:
        return False
    try:
        w = ev.get("write_errno")
        r = ev.get("rename_errno")
        l = ev.get("link_errno")
        bw = ev.get("backing_writable_by_1001")
    except Exception:
        return False
    if w != errno.EROFS or r != errno.EROFS or l != errno.EROFS:
        return False
    if bw is True:
        return False
    if bw is None:
        # require explicit False; missing means unobserved
        return False
    return True


def build_portable_manifest(records, evidence=None):
    gates_empty = _gates_unexecuted()
    if not isinstance(records, (list, tuple)):
        return {
            "status": "manifest-refused",
            "signed": False,
            "activation": "UNEXECUTED",
            "service_cutover": "NOT_AUTHORIZED",
            "kernel_immutable": False,
            "gates": gates_empty,
            "images": [],
            "error": "records type",
        }
    images = []
    for rec in records:
        if not isinstance(rec, dict):
            return {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": gates_empty,
                "images": [],
                "error": "record type",
            }
        kind = rec.get("kind")
        image_path = rec.get("image_path")
        prep_path = rec.get("prep_path")
        expected = rec.get("expected_sha256")
        if kind not in ("known-good", "candidate"):
            return {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": gates_empty,
                "images": [],
                "error": "kind",
            }
        if not isinstance(image_path, str) or not image_path:
            return {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": gates_empty,
                "images": [],
                "error": "image_path",
            }
        if not isinstance(prep_path, str) or not prep_path:
            return {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": gates_empty,
                "images": [],
                "error": "prep_path",
            }
        if not isinstance(expected, str) or not expected:
            return {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": gates_empty,
                "images": [],
                "error": "expected_sha256",
            }
        try:
            actual = _sha256_file(image_path)
        except OSError as e:
            return {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": gates_empty,
                "images": [],
                "error": f"sha read: {e}",
            }
        if actual != expected:
            return {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": gates_empty,
                "images": [],
                "error": "sha mismatch",
            }
        dest, mount, digest = _dest_for_kind(kind)
        rec_ev = rec.get("evidence", rec.get("observations", rec.get("host_observation")))
        ev = _evidence_for_kind(rec_ev, evidence, kind)
        observed = isinstance(ev, dict) and ev.get("executed") is True and len([k for k in ev if k != "executed"]) > 0
        # Bare true flag alone is not observed (needs extra fields)
        if isinstance(ev, dict) and ev.get("executed") is True and len(ev) <= 1:
            observed = False
        imm = _immutable_from_evidence(ev) if observed else False
        images.append({
            "kind": kind,
            "image_path": image_path,
            "prep_path": prep_path,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "destination": dest,
            "mount": mount,
            "digest": digest,
            "observed": bool(observed),
            "unobserved": not bool(observed),
            "kernel_immutable": bool(imm),
            "signed": False,
            "activation": "UNEXECUTED",
        })
    # global gates: caller evidence may only mark A1/C2 via EROFS, never others.
    if isinstance(evidence, dict) and "executed" in evidence:
        gates = _gates_from_evidence(evidence)
    else:
        gates = _gates_unexecuted()
        if images:
            all_imm = True
            for img, rec in zip(images, records):
                rec_ev = rec.get("evidence", rec.get("observations", rec.get("host_observation")))
                ev = _evidence_for_kind(rec_ev, evidence, rec.get("kind"))
                if not _immutable_from_evidence(ev):
                    all_imm = False
                    break
            if all_imm:
                gates["A1"] = "EXECUTED"
                gates["C2"] = "EXECUTED"
    global_imm = bool(images) and all(i.get("kernel_immutable") for i in images)
    return {
        "status": "manifest-ready",
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "NOT_AUTHORIZED",
        "kernel_immutable": bool(global_imm),
        "gates": gates,
        "images": images,
    }


def _is_forbidden_manifest_out(path):
    if not isinstance(path, str) or not path:
        return True
    norm = os.path.normpath(path)
    if not os.path.isabs(norm):
        return True
    for prefix in _FORBIDDEN_MANIFEST_OUT:
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    return False


def plan(records, ports, manifest_out=None, host=None):
    # Validate ports early (refuse 9119/4096)
    try:
        port_map = {}
        if isinstance(ports, dict):
            port_map = dict(ports)
        elif isinstance(ports, (list, tuple)):
            # assign in record order
            for i, rec in enumerate(records or []):
                if i < len(ports):
                    k = rec.get("kind") if isinstance(rec, dict) else str(i)
                    port_map[k] = ports[i]
        elif ports is None:
            port_map = {}
        else:
            port_map = {}
        for _k, _p in list(port_map.items()):
            # web_proof_argv validates; use dummy mount for check
            try:
                web_proof_argv("/run/hermes-stock-activation/known-good-snap", _p)
            except ValueError:
                m = {
                    "status": "manifest-refused",
                    "signed": False,
                    "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED",
                    "kernel_immutable": False,
                    "gates": _gates_unexecuted(),
                    "images": [],
                    "error": "refused port",
                }
                return {"status": "manifest-refused", "manifest": m, "commands": []}
    except Exception:
        pass
    # evidence for plan: none (no spawn) -> unobserved
    manifest = build_portable_manifest(records)
    if manifest.get("status") != "manifest-ready":
        return {"status": "manifest-refused", "manifest": manifest, "commands": []}
    commands = []
    # install dirs (dedup)
    seen_install = set()
    for img in manifest.get("images", []):
        kind = img["kind"]
        _dest, mount, _digest = _dest_for_kind(kind)
        for d, mode in ((LIB_DIR, "0700"), (BACKING_DIR, "0700"),
                        (RUN_DIR, "0755"), (mount, "0755")):
            key = (d, mode)
            if key not in seen_install:
                seen_install.add(key)
                commands.append(install_dir_argv(d, mode))
    # per-image losetup/mount/findmnt/proof
    for img in manifest.get("images", []):
        kind = img["kind"]
        dest, mount, _digest = _dest_for_kind(kind)
        commands.append(losetup_argv(dest))
        # placeholder loop for subsequent commands in plan (no spawn so unknown)
        loop_ph = "/dev/loopX"
        commands.append(mount_argv(loop_ph, mount))
        commands.append(findmnt_argv(mount))
        commands.append(cli_proof_argv(mount, "--help"))
        commands.append(cli_proof_argv(mount, "--version"))
        # web proof port
        port = None
        if isinstance(ports, dict):
            port = ports.get(kind)
            if port is None:
                # try first value
                port = next(iter(ports.values()), None) if ports else None
        if port is not None:
            try:
                commands.append(web_proof_argv(mount, port))
            except ValueError:
                return {"status": "manifest-refused", "manifest": {
                    "status": "manifest-refused", "signed": False,
                    "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                    "kernel_immutable": False, "gates": _gates_unexecuted(),
                    "images": [], "error": "refused port"}, "commands": []}
        commands.append(umount_argv(mount))
        commands.append(losetup_detach_argv(loop_ph))
    result = {"status": manifest.get("status", "manifest-ready"),
              "manifest": manifest, "commands": commands}
    if manifest_out is not None:
        if _is_forbidden_manifest_out(manifest_out):
            refused = {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": _gates_unexecuted(),
                "images": [],
                "error": "manifest_out forbidden",
            }
            return {"status": "manifest-refused", "manifest": refused, "commands": []}
        # fixture containment when host has fixture_root
        if host is not None:
            root = getattr(host, "fixture_root", None) or getattr(host, "_root", None)
            if isinstance(root, str) and os.path.isabs(root):
                norm_out = os.path.normpath(manifest_out)
                norm_root = os.path.normpath(root)
                if norm_out != norm_root and not norm_out.startswith(norm_root + "/"):
                    refused = {
                        "status": "manifest-refused",
                        "signed": False,
                        "activation": "UNEXECUTED",
                        "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False,
                        "gates": _gates_unexecuted(),
                        "images": [],
                        "error": "manifest_out outside fixture",
                    }
                    return {"status": "manifest-refused", "manifest": refused, "commands": []}
        else:
            # no host -> do not write
            return result
        # write with fsync via host if available else os
        try:
            data = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
            if host is not None and all(hasattr(host, m) for m in ("write_temp", "file_fsync", "rename_path", "dir_fsync")):
                tmp = manifest_out + ".tmp.plan"
                host.write_temp(tmp, data)
                host.file_fsync(tmp)
                host.rename_path(tmp, manifest_out)
                parent = os.path.dirname(os.path.normpath(manifest_out))
                if parent and parent != "":
                    host.dir_fsync(parent)
            else:
                tmp = manifest_out + ".tmp.plan"
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                fd = os.open(tmp, flags, 0o644)
                try:
                    off = 0
                    while off < len(data):
                        n = os.write(fd, data[off:])
                        if n == 0:
                            raise OSError("short write")
                        off += n
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.rename(tmp, manifest_out)
                parent = os.path.dirname(os.path.normpath(manifest_out))
                if parent:
                    dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(dfd)
                    finally:
                        os.close(dfd)
        except OSError:
            refused = {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": _gates_unexecuted(),
                "images": [],
                "error": "manifest write failed",
            }
            return {"status": "manifest-refused", "manifest": refused, "commands": []}
    return result


_REQUIRED_HOST_METHODS = (
    "lstat", "read_bytes", "sha256_file", "write_temp",
    "file_fsync", "rename_path", "dir_fsync", "run",
    "denial_probe", "file_uid",
)


def _host_missing(host):
    missing = []
    for m in _REQUIRED_HOST_METHODS:
        fn = getattr(host, m, None)
        if not callable(fn):
            missing.append(m)
    return missing


def _coerce_run_result(res):
    rc = getattr(res, "returncode", 1)
    out = getattr(res, "stdout", b"")
    err = getattr(res, "stderr", b"")
    if isinstance(out, bytes):
        try:
            out_s = out.decode("utf-8", "replace")
        except Exception:
            out_s = ""
    elif isinstance(out, str):
        out_s = out
    else:
        out_s = str(out)
    if isinstance(err, bytes):
        try:
            err_s = err.decode("utf-8", "replace")
        except Exception:
            err_s = ""
    elif isinstance(err, str):
        err_s = err
    else:
        err_s = str(err)
    return rc, out_s, err_s


def _lstat_mode_uid(host, path):
    st = host.lstat(path)
    if isinstance(st, dict):
        mode = st.get("mode", st.get("st_mode"))
        uid = st.get("uid", st.get("st_uid"))
        is_link = st.get("is_symlink", st.get("is_link", False))
        if isinstance(mode, int):
            mode = stat.S_IMODE(mode)
        return mode, uid, bool(is_link), st
    mode_full = getattr(st, "st_mode", None)
    uid = getattr(st, "st_uid", None)
    if mode_full is None:
        return None, uid, False, st
    is_link = stat.S_ISLNK(mode_full)
    return stat.S_IMODE(mode_full), uid, is_link, st


def _lstat_full(host, path):
    st = host.lstat(path)
    if isinstance(st, dict):
        mode = st.get("mode", st.get("st_mode"))
        uid = st.get("uid", st.get("st_uid"))
        gid = st.get("gid", st.get("st_gid", 0))
        is_link = st.get("is_symlink", st.get("is_link", False))
        if isinstance(mode, int):
            # dict may hold full st_mode or already masked; normalize
            try:
                mode = stat.S_IMODE(mode)
            except Exception:
                pass
        return mode, uid, gid, bool(is_link), st
    mode_full = getattr(st, "st_mode", None)
    uid = getattr(st, "st_uid", None)
    gid = getattr(st, "st_gid", None)
    if gid is None:
        gid = 0
    if mode_full is None:
        return None, uid, gid, False, st
    return stat.S_IMODE(mode_full), uid, gid, stat.S_ISLNK(mode_full), st


def _backing_writable_by_1001_from_lstat(mode, uid, gid):
    # False only when lstat proves uid 1001 cannot write; unknown -> True (writable)
    try:
        if mode is None:
            return True
        if mode & 0o002:
            return True
        if uid == 1001 and (mode & 0o200):
            return True
        if gid == 1001 and (mode & 0o020):
            return True
        return False
    except Exception:
        return True


def _parse_losetup_list(out_s, dest):
    try:
        txt = out_s.strip()
        if not txt:
            return False
        # --noheadings may still emit one line per device; require exactly one line
        lines = [l for l in txt.splitlines() if l.strip()]
        if len(lines) != 1:
            return False
        parts = lines[0].strip().split(None, 1)
        if len(parts) != 2:
            return False
        ro, back = parts[0].strip(), parts[1].strip()
        if ro != "1":
            return False
        if back != dest:
            return False
        return True
    except Exception:
        return False


def _digest_payload(kind, sha_hex):
    return (json.dumps({"kind": kind, "sha256": sha_hex, "signed": False},
                       sort_keys=True) + "\n").encode("utf-8")


def _findmnt_ok(out_s, loop):
    if "squashfs" not in out_s:
        return False
    if "ro" not in out_s:
        return False
    if loop not in out_s:
        return False
    # must not contain rw or bind as option tokens
    # Use simple token check: split on non-alnum? Use substring but avoid
    # false positive from "ro" inside other words is already accepted.
    # For rw/bind, check comma/space separated options.
    low = out_s
    # crude: look for standalone rw / bind options
    # split by comma, space, newline, tab
    import re
    toks = re.split(r"[\s,]+", low)
    if "rw" in toks:
        return False
    if "bind" in toks:
        return False
    # also catch "rw" inside options like "rw,nosuid"? already tokenized
    return True


def apply(host, records, ports, execute_commands=True):
    missing = _host_missing(host)
    if missing:
        return {"status": "refused", "reason": f"missing host methods: {','.join(missing)}",
                "signed": False, "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                "gates": _gates_unexecuted(), "images": []}
    if not isinstance(records, (list, tuple)) or not records:
        return {"status": "refused", "reason": "records",
                "signed": False, "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                "gates": _gates_unexecuted(), "images": []}
    # validate ports (refuse 9119/4096)
    port_map = ports if isinstance(ports, dict) else {}
    for _k, _p in list(port_map.items()) if isinstance(port_map, dict) else []:
        try:
            web_proof_argv("/run/hermes-stock-activation/known-good-snap", _p)
        except ValueError:
            return {"status": "refused", "reason": "refused port",
                    "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": []}
    # sha precheck via host.sha256_file on source images
    for rec in records:
        if not isinstance(rec, dict):
            return {"status": "manifest-refused", "signed": False,
                    "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                    "kernel_immutable": False, "gates": _gates_unexecuted(), "images": []}
        for k in ("kind", "image_path", "prep_path", "expected_sha256"):
            if k not in rec:
                return {"status": "manifest-refused", "signed": False,
                        "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False, "gates": _gates_unexecuted(), "images": []}
        if rec.get("kind") not in ("known-good", "candidate"):
            return {"status": "manifest-refused", "signed": False,
                    "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                    "kernel_immutable": False, "gates": _gates_unexecuted(), "images": []}
        try:
            actual_src = host.sha256_file(rec["image_path"])
        except OSError:
            return {"status": "manifest-refused", "signed": False,
                    "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                    "kernel_immutable": False, "gates": _gates_unexecuted(), "images": []}
        except Exception:
            return {"status": "manifest-refused", "signed": False,
                    "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                    "kernel_immutable": False, "gates": _gates_unexecuted(), "images": []}
        if actual_src != rec["expected_sha256"]:
            return {"status": "manifest-refused", "signed": False,
                    "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                    "kernel_immutable": False, "gates": _gates_unexecuted(), "images": []}
    results = []
    overall_immutable = True
    # Per-image observed flags for EXECUTED gates. Only this invocation counts.
    prov_flags = []
    mount_flags = []
    a1c2_flags = []
    cli_flags = []
    web_flags = []
    digest_flags = []
    for rec in records:
        kind = rec["kind"]
        src = rec["image_path"]
        expected = rec["expected_sha256"]
        dest, mount, digest_path = _dest_for_kind(kind)
        port = port_map.get(kind) if isinstance(port_map, dict) else None
        # destination present?
        dest_exists = True
        try:
            host.lstat(dest)
        except FileNotFoundError:
            dest_exists = False
        except OSError as e:
            # treat missing similarly? if other OSError, durable unknown?
            if getattr(e, "errno", None) in (2,):
                dest_exists = False
            else:
                return {"status": "durable-state-unknown", "signed": False,
                        "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False, "gates": _gates_unexecuted(), "images": results}
        except Exception:
            dest_exists = False
        parent = os.path.dirname(dest)
        # parent symlink check; parent lstat OSError is refusal, not "not a symlink"
        try:
            pst = host.lstat(parent)
            if isinstance(pst, dict):
                parent_link = bool(pst.get("is_symlink", pst.get("is_link", False)))
            else:
                parent_link = stat.S_ISLNK(getattr(pst, "st_mode", 0))
            if parent_link:
                return {"status": "refused", "reason": "parent symlink",
                        "signed": False, "activation": "UNEXECUTED",
                        "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                        "gates": _gates_unexecuted(), "images": results}
        except FileNotFoundError:
            # parent missing -> need install
            parent_link = False
        except OSError as e:
            # Any other parent lstat OSError is refusal (not "not a symlink").
            if getattr(e, "errno", None) in (2,):
                parent_link = False
            else:
                return {"status": "refused", "reason": "parent lstat",
                        "signed": False, "activation": "UNEXECUTED",
                        "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                        "gates": _gates_unexecuted(), "images": results}
        # foreign owner / mode / symlink refuses before mutation; never chmod to fix
        if dest_exists:
            try:
                _omode, _ouid, _ogid, _olink, _ = _lstat_full(host, dest)
            except Exception:
                return {"status": "refused", "reason": "dest lstat",
                        "signed": False, "activation": "UNEXECUTED",
                        "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                        "gates": _gates_unexecuted(), "images": results}
            if _olink or _ouid != 0 or _ogid != 0 or _omode != 0o400:
                return {"status": "refused", "reason": "foreign owner",
                        "signed": False, "activation": "UNEXECUTED",
                        "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                        "gates": _gates_unexecuted(), "images": results}
        # idempotent check when dest exists
        if dest_exists:
            try:
                dmode, duid, dgid, dlink, _ = _lstat_full(host, dest)
                dsha = host.sha256_file(dest)
            except (OSError, Exception):
                dsha, dmode, duid, dgid, dlink = None, None, None, None, None
            idem = (dsha == expected and dmode == 0o400 and duid == 0 and dgid == 0 and not dlink)
            if idem:
                # findmnt must show same RO loop
                try:
                    if execute_commands:
                        fres = host.run(findmnt_argv(mount), PROOF_ENV)
                    else:
                        fres = None
                    if fres is not None:
                        _rc, out_s, _e = _coerce_run_result(fres)
                        # extract loop: look for /dev/loop
                        import re
                        m = re.search(r"/dev/loop\d+", out_s)
                        loop_found = m.group(0) if m else ""
                        if loop_found and _findmnt_ok(out_s, loop_found):
                            # Idempotent sha/mode/uid observed: PROVISION counts.
                            # This invocation did not run losetup/mount/probes/cli/web/digest.
                            prov_flags.append(True)
                            mount_flags.append(False)
                            a1c2_flags.append(False)
                            cli_flags.append(False)
                            web_flags.append(False)
                            # Digest: check existing digest file matches without rewrite.
                            try:
                                _dmode, _duid, _dgid, _dlink, _ = _lstat_full(host, digest_path)
                                _ddata = host.read_bytes(digest_path)
                                _exp = _digest_payload(kind, expected)
                                if (_ddata == _exp and _dmode == 0o400 and _duid == 0
                                        and _dgid == 0 and not _dlink):
                                    digest_flags.append(True)
                                else:
                                    digest_flags.append(False)
                            except Exception:
                                digest_flags.append(False)
                            results.append({"kind": kind, "status": "idempotent",
                                            "destination": dest, "mount": mount,
                                            "kernel_immutable": False, "observed": False})
                            continue
                        # not idempotent mount -> fall through to full path.
                        # If findmnt does not show RO loop, we need to mount
                        # but dest already matches; still need mount steps.
                    else:
                        # execute_commands False: record only, treat as idempotent candidate
                        results.append({"kind": kind, "status": "idempotent",
                                        "destination": dest, "mount": mount,
                                        "kernel_immutable": False, "observed": False})
                        continue
                except Exception:
                    pass
        # install dirs when dest absent; nonzero status is failure, not ignored
        if not dest_exists:
            provision_this = False
            for d, mode in ((LIB_DIR, "0700"), (BACKING_DIR, "0700"),
                            (RUN_DIR, "0755"), (mount, "0755")):
                if execute_commands:
                    try:
                        ires = host.run(install_dir_argv(d, mode), PROOF_ENV)
                    except Exception:
                        return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                                "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                                "gates": _gates_unexecuted(), "images": results}
                    irc, _, _ = _coerce_run_result(ires)
                    if irc != 0:
                        return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                                "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                                "gates": _gates_unexecuted(), "images": results}
                else:
                    # argv recording only: still record? For False mode tests expect
                    # commands recorded without run? Our contract: when False, do not call run.
                    pass
            # copy bytes
            try:
                data = host.read_bytes(src)
            except OSError:
                return {"status": "durable-state-unknown", "signed": False,
                        "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False, "gates": _gates_unexecuted(), "images": results}
            tmp = dest + ".tmp.operator-proof"
            try:
                host.write_temp(tmp, data)
                host.file_fsync(tmp)
                host.rename_path(tmp, dest)
                host.dir_fsync(parent)
                provision_this = True
            except OSError:
                return {"status": "durable-state-unknown", "signed": False,
                        "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False, "gates": _gates_unexecuted(), "images": results}
            except Exception:
                return {"status": "durable-state-unknown", "signed": False,
                        "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False, "gates": _gates_unexecuted(), "images": results}
        else:
            # dest already matched sha but mount not idempotent: PROVISION counts
            # via idempotent sha/mode/uid match (no copy needed in this invocation).
            provision_this = True
        # losetup
        if not execute_commands:
            # argv recording mode: return commands without spawn
            cmds = [install_dir_argv(LIB_DIR, "0700"), install_dir_argv(BACKING_DIR, "0700"),
                    install_dir_argv(RUN_DIR, "0755"), install_dir_argv(mount, "0755"),
                    losetup_argv(dest), mount_argv("/dev/loopX", mount),
                    findmnt_argv(mount)]
            results.append({"kind": kind, "status": "recorded", "commands": cmds,
                            "destination": dest, "mount": mount})
            continue
        try:
            lres = host.run(losetup_argv(dest), PROOF_ENV)
        except Exception:
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        lrc, lout, _le = _coerce_run_result(lres)
        loop = lout.strip().splitlines()
        # must be one device and nonzero status is failure
        if lrc != 0 or len(loop) != 1:
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        loopdev = loop[0].strip()
        if not loopdev.startswith("/dev/loop") or " " in loopdev or "\t" in loopdev:
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        # Before mount: verify RO and BACK-FILE via losetup --list.
        # Ignore of back-file is not allowed.
        try:
            llist = host.run(losetup_list_argv(loopdev), PROOF_ENV)
        except Exception:
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        llrc, llout, _lle = _coerce_run_result(llist)
        if llrc != 0 or not _parse_losetup_list(llout, dest):
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        mount_this = False
        try:
            mres = host.run(mount_argv(loopdev, mount), PROOF_ENV)
        except Exception:
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        mrc, _mout, _me = _coerce_run_result(mres)
        if mrc != 0:
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        try:
            fres = host.run(findmnt_argv(mount), PROOF_ENV)
        except Exception:
            try:
                host.run(umount_argv(mount), PROOF_ENV)
            except Exception:
                pass
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        frc, fout, _fe = _coerce_run_result(fres)
        if frc != 0 or not _findmnt_ok(fout, loopdev):
            try:
                host.run(umount_argv(mount), PROOF_ENV)
            except Exception:
                pass
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        mount_this = True
        # denial probes: A1/C2 only when errnos are EROFS and backing not writable
        # by 1001 from lstat, not from caller flag.
        try:
            w = host.denial_probe(mount, "write")
            r = host.denial_probe(mount, "rename")
            li = host.denial_probe(mount, "link")
        except Exception:
            try:
                host.run(umount_argv(mount), PROOF_ENV)
            except Exception:
                pass
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        # normalize errno values (may be int or dict)
        def _to_errno(v):
            if isinstance(v, int):
                return v
            if isinstance(v, dict):
                for k in ("errno", "code", "err"):
                    if k in v and isinstance(v[k], int):
                        return v[k]
                return None
            e = getattr(v, "errno", None)
            if isinstance(e, int):
                return e
            return None
        w_e, r_e, l_e = _to_errno(w), _to_errno(r), _to_errno(li)
        imm = (w_e == errno.EROFS and r_e == errno.EROFS and l_e == errno.EROFS)
        # backing_writable_by_1001 from lstat, not caller flag.
        try:
            bmode, buid, bgid, _bl, _bs = _lstat_full(host, dest)
            if _backing_writable_by_1001_from_lstat(bmode, buid, bgid):
                imm = False
            # also require dest still uid 0/gid 0 (already refused otherwise)
            if buid != 0 or bgid != 0:
                imm = False
        except Exception:
            imm = False
        if not imm:
            overall_immutable = False
        a1c2_this = bool(imm)
        # CLI + web proof
        cli_ok = True
        for flag in ("--help", "--version"):
            try:
                cres = host.run(cli_proof_argv(mount, flag), PROOF_ENV)
            except Exception:
                cli_ok = False
                break
            crc, _cout, _ce = _coerce_run_result(cres)
            if crc != 0:
                cli_ok = False
                break
        cli_this = bool(cli_ok)
        web_this = False
        dashboard_ok = True
        if cli_ok and port is not None:
            try:
                wargv = web_proof_argv(mount, port)
            except ValueError:
                dashboard_ok = False
                wargv = None
            if wargv is not None:
                try:
                    wres = host.run(wargv, PROOF_ENV)
                except Exception:
                    dashboard_ok = False
                else:
                    wrc, _wout, _we = _coerce_run_result(wres)
                    if wrc != 0:
                        dashboard_ok = False
                    else:
                        # Dashboard argv exit alone is not web proof.
                        # Require health fetch 200 + json + ok true for WEB_PROOF.
                        # Health failure leaves WEB_PROOF UNEXECUTED but does not
                        # fail the overall apply (only dashboard argv failure does).
                        try:
                            hfn = getattr(host, "health_fetch", None)
                            if not callable(hfn):
                                web_this = False
                            else:
                                hres = hfn(_dashboard_url(port))
                                if isinstance(hres, dict):
                                    hs = hres.get("status")
                                    hc = hres.get("content_type", hres.get("content-type", ""))
                                    hb = hres.get("body")
                                else:
                                    hs = getattr(hres, "status", None)
                                    hc = getattr(hres, "content_type", "")
                                    hb = getattr(hres, "body", None)
                                if _health_ok(hs, hc, hb):
                                    web_this = True
                                else:
                                    web_this = False
                        except Exception:
                            web_this = False
            # port None means no web proof attempted in this invocation
            if port is None:
                dashboard_ok = True
                web_this = False
        elif cli_ok and port is None:
            dashboard_ok = True
            web_this = False
        if not (cli_ok and dashboard_ok):
            try:
                host.run(umount_argv(mount), PROOF_ENV)
            except Exception:
                pass
            try:
                host.run(losetup_detach_argv(loopdev), PROOF_ENV)
            except Exception:
                pass
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        # DIGEST: unsigned digest file with signed false, fsync, rename, dir fsync,
        # readback match, mode 0400. Write to reviewed digest path for kind.
        digest_this = False
        try:
            exp_payload = _digest_payload(kind, expected)
            # If existing digest already matches with 0400/uid0, count as observed.
            try:
                emode, euid, egid, elink, _ = _lstat_full(host, digest_path)
                edata = host.read_bytes(digest_path)
                if (edata == exp_payload and emode == 0o400 and euid == 0
                        and egid == 0 and not elink):
                    digest_this = True
                else:
                    raise OSError("digest mismatch")
            except Exception:
                # Need to write digest file.
                dtmp = digest_path + ".tmp.operator-proof"
                dparent = os.path.dirname(digest_path)
                try:
                    host.write_temp(dtmp, exp_payload)
                    host.file_fsync(dtmp)
                    host.rename_path(dtmp, digest_path)
                    host.dir_fsync(dparent)
                    rdata = host.read_bytes(digest_path)
                    rmode, ruid, rgid, rlink, _ = _lstat_full(host, digest_path)
                    if (rdata == exp_payload and rmode == 0o400 and ruid == 0
                            and rgid == 0 and not rlink):
                        digest_this = True
                    else:
                        digest_this = False
                except Exception:
                    digest_this = False
        except Exception:
            digest_this = False
        prov_flags.append(bool(provision_this))
        mount_flags.append(bool(mount_this))
        a1c2_flags.append(bool(a1c2_this))
        cli_flags.append(bool(cli_this))
        web_flags.append(bool(web_this))
        digest_flags.append(bool(digest_this))
        results.append({"kind": kind, "status": "applied", "destination": dest,
                        "mount": mount, "loop": loopdev,
                        "kernel_immutable": bool(imm), "observed": True})
    # never unlink journal: we never call unlink/remove
    # Gates EXECUTED only when this invocation observed them for every applied image.
    def _all(flags):
        return bool(flags) and all(bool(x) for x in flags)
    gates = _gates_unexecuted()
    if _all(prov_flags):
        gates["PROVISION"] = "EXECUTED"
    if _all(mount_flags):
        gates["MOUNT"] = "EXECUTED"
    if _all(a1c2_flags):
        gates["A1"] = "EXECUTED"
        gates["C2"] = "EXECUTED"
    if _all(cli_flags):
        gates["CLI_PROOF"] = "EXECUTED"
    if _all(web_flags):
        gates["WEB_PROOF"] = "EXECUTED"
    if _all(digest_flags):
        gates["DIGEST"] = "EXECUTED"
    return {"status": "applied", "signed": False, "activation": "UNEXECUTED",
            "service_cutover": "NOT_AUTHORIZED",
            "kernel_immutable": bool(overall_immutable) if results else False,
            "gates": gates, "images": results}


def recover(host, mounts):
    if not isinstance(mounts, (list, tuple)):
        return {"status": "stopped-unresolved", "images": []}
    # host must have run
    run = getattr(host, "run", None)
    if not callable(run):
        return {"status": "stopped-unresolved", "images": []}
    out = []
    for mp in mounts:
        if not isinstance(mp, str) or not mp:
            return {"status": "stopped-unresolved", "images": out}
        try:
            fres = run(findmnt_argv(mp), PROOF_ENV)
        except Exception:
            out.append({"mount": mp, "status": "not-mounted"})
            continue
        _rc, fout, _fe = _coerce_run_result(fres)
        if _rc != 0 or not fout.strip():
            out.append({"mount": mp, "status": "not-mounted"})
            continue
        import re
        loops = re.findall(r"/dev/loop\d+", fout)
        uniq = sorted(set(loops))
        if len(uniq) != 1:
            return {"status": "stopped-unresolved", "images": out}
        # ambiguous if multiple lines with different sources?
        lines = [l for l in fout.strip().splitlines() if l.strip()]
        if len(lines) != 1:
            # if findmnt returns one line, ok; else ambiguous
            # Allow single logical entry even with newline? Require exactly 1 loop and squashfs+ro
            if len(lines) > 1:
                return {"status": "stopped-unresolved", "images": out}
        loopdev = uniq[0]
        if "squashfs" not in fout or "ro" not in fout:
            out.append({"mount": mp, "status": "not-mounted"})
            continue
        try:
            ures = run(umount_argv(mp), PROOF_ENV)
        except Exception:
            return {"status": "stopped-unresolved", "images": out}
        try:
            urc, _, _ = _coerce_run_result(ures)
        except Exception:
            return {"status": "stopped-unresolved", "images": out}
        if urc != 0:
            return {"status": "stopped-unresolved", "images": out}
        try:
            dres = run(losetup_detach_argv(loopdev), PROOF_ENV)
        except Exception:
            return {"status": "stopped-unresolved", "images": out}
        try:
            drc, _, _ = _coerce_run_result(dres)
        except Exception:
            return {"status": "stopped-unresolved", "images": out}
        if drc != 0:
            return {"status": "stopped-unresolved", "images": out}
        out.append({"mount": mp, "status": "stopped", "loop": loopdev})
    # does not delete journal, no daemon
    if not out:
        return {"status": "stopped", "images": out}
    if all(i.get("status") in ("stopped", "not-mounted") for i in out):
        # if any stopped, overall stopped else not-mounted
        if any(i.get("status") == "stopped" for i in out):
            return {"status": "stopped", "images": out}
        return {"status": "not-mounted", "images": out}
    return {"status": "stopped-unresolved", "images": out}


def _live_file_ok():
    try:
        p = __file__
    except NameError:
        return False, "no file"
    try:
        if os.path.islink(p):
            return False, "symlink"
        st = os.lstat(p)
    except OSError as e:
        return False, str(e)
    if st.st_uid != 0:
        return False, "uid"
    if stat.S_IMODE(st.st_mode) != 0o500:
        return False, "mode"
    norm = os.path.normpath(p)
    # __file__ may be relative; resolve against cwd
    if not os.path.isabs(norm):
        norm = os.path.normpath(os.path.join(os.getcwd(), norm))
    if norm != RECOVERY_PREFIX and not norm.startswith(RECOVERY_PREFIX + "/"):
        return False, "path"
    return True, ""


_DENIAL_PROBE_CODE = (
    "import os,sys,errno\n"
    "mount=sys.argv[1]\n"
    "op=sys.argv[2]\n"
    "wp=os.path.join(mount,'.proof-write-1001')\n"
    "rs=os.path.join(mount,'.proof-rename-src-1001')\n"
    "rd=os.path.join(mount,'.proof-rename-dst-1001')\n"
    "ls=os.path.join(mount,'.proof-link-src-1001')\n"
    "ld=os.path.join(mount,'.proof-link-dst-1001')\n"
    "def _emit(n):\n"
    "    print(n)\n"
    "try:\n"
    "    assert isinstance(mount,str) and isinstance(op,str)\n"
    "    if op=='write':\n"
    "        try:\n"
    "            fd=os.open(wp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\n"
    "        except OSError as e:\n"
    "            _emit(e.errno or 1)\n"
    "        else:\n"
    "            try:\n"
    "                os.close(fd)\n"
    "            except Exception:\n"
    "                pass\n"
    "            try:\n"
    "                os.unlink(wp)\n"
    "            except Exception:\n"
    "                pass\n"
    "            _emit(0)\n"
    "    elif op=='rename':\n"
    "        try:\n"
    "            os.rename(rs,rd)\n"
    "            try:\n"
    "                os.unlink(rd)\n"
    "            except Exception:\n"
    "                pass\n"
    "            _emit(0)\n"
    "        except OSError as e:\n"
    "            if e.errno==errno.ENOENT:\n"
    "                try:\n"
    "                    fd=os.open(rs,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\n"
    "                except OSError as e2:\n"
    "                    _emit(e2.errno or 1)\n"
    "                else:\n"
    "                    try:\n"
    "                        os.close(fd)\n"
    "                    except Exception:\n"
    "                        pass\n"
    "                    try:\n"
    "                        os.rename(rs,rd)\n"
    "                        _emit(0)\n"
    "                        try:\n"
    "                            os.unlink(rd)\n"
    "                        except Exception:\n"
    "                            pass\n"
    "                    except OSError as e3:\n"
    "                        _emit(e3.errno or 1)\n"
    "                        try:\n"
    "                            os.unlink(rs)\n"
    "                        except Exception:\n"
    "                            pass\n"
    "            else:\n"
    "                _emit(e.errno or 1)\n"
    "    elif op=='link':\n"
    "        try:\n"
    "            fd=os.open(ls,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\n"
    "        except OSError as e2:\n"
    "            if e2.errno!=errno.EEXIST:\n"
    "                _emit(e2.errno or 1)\n"
    "            else:\n"
    "                pass\n"
    "        else:\n"
    "            try:\n"
    "                os.close(fd)\n"
    "            except Exception:\n"
    "                pass\n"
    "        try:\n"
    "            try:\n"
    "                os.unlink(ld)\n"
    "            except FileNotFoundError:\n"
    "                pass\n"
    "            os.link(ls,ld)\n"
    "            _emit(0)\n"
    "            try:\n"
    "                os.unlink(ls)\n"
    "            except Exception:\n"
    "                pass\n"
    "            try:\n"
    "                os.unlink(ld)\n"
    "            except Exception:\n"
    "                pass\n"
    "        except OSError as e:\n"
    "            _emit(e.errno or 1)\n"
    "            try:\n"
    "                os.unlink(ls)\n"
    "            except Exception:\n"
    "                pass\n"
    "            try:\n"
    "                os.unlink(ld)\n"
    "            except Exception:\n"
    "                pass\n"
    "    else:\n"
    "        _emit(1)\n"
    "except Exception:\n"
    "    print(1)\n"
)


class LiveProofHost:
    """Stdlib live host. Uses os and subprocess only. Never imports scripts.stock_activation."""

    def lstat(self, path):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        return os.lstat(path)

    def read_bytes(self, path):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        with open(path, "rb") as f:
            return f.read()

    def sha256_file(self, path):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(65536)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()

    def write_temp(self, path, data):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data type")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o400)
        try:
            view = bytes(data)
            off = 0
            while off < len(view):
                n = os.write(fd, view[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        else:
            os.close(fd)

    def file_fsync(self, path):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def rename_path(self, src, dst):
        if isinstance(src, bool) or isinstance(dst, bool):
            raise TypeError("bool path refused")
        os.rename(src, dst)

    def dir_fsync(self, path):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def file_uid(self, path):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        return os.lstat(path).st_uid

    def run(self, argv, env):
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            raise RuntimeError("argv refused")
        # Reject blocked basenames and forbidden path fragments in any element.
        for el in argv:
            base = os.path.basename(el)
            if base in ("systemctl", "git", "sudo", "hermes"):
                raise RuntimeError("blocked basename")
            if "/opt" in el or "cutover_" in el:
                raise RuntimeError("blocked path")
        prog = argv[0]
        if not os.path.isabs(prog):
            raise RuntimeError("absolute required")
        allowed_exact = {
            "/usr/bin/install",
            "/usr/sbin/losetup",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/bin/findmnt",
        }
        is_python = (
            prog.startswith(RUN_DIR + "/")
            and os.path.basename(prog) == "python3"
            and len(argv) > 1
            and argv[1] == "-I"
        )
        if prog not in allowed_exact and not is_python:
            raise RuntimeError("not allowed")
        if env != PROOF_ENV:
            raise RuntimeError("env refused")
        return subprocess.run(argv, shell=False, env=PROOF_ENV, capture_output=True, check=False)

    def denial_probe(self, path, op):
        if isinstance(path, bool):
            raise TypeError("bool path refused")
        if op not in ("write", "rename", "link"):
            raise ValueError("op")
        if not isinstance(path, str) or not path:
            raise ValueError("path")
        argv = [
            "/usr/bin/sudo",
            "-n",
            "-u",
            "#1001",
            "/usr/bin/python3.12",
            "-I",
            "-c",
            _DENIAL_PROBE_CODE,
            path,
            op,
        ]
        # Must not use systemctl; uses sudo + absolute python3.12 only.
        for el in argv:
            if "systemctl" in el:
                raise RuntimeError("systemctl forbidden")
        try:
            cp = subprocess.run(argv, shell=False, env=PROOF_ENV,
                                capture_output=True, check=False, timeout=15)
        except Exception:
            # If sudo/probe cannot run, return a non-EROFS errno so gates stay UNEXECUTED.
            return 1
        try:
            out = cp.stdout.decode("utf-8", "replace").strip().split()
            if not out:
                return 1
            return int(out[-1])
        except Exception:
            return 1

    def health_fetch(self, url):
        # Stdlib HTTP fetch for dashboard health. No systemctl, no sudo.
        try:
            import urllib.parse as _up
            import http.client as _hc
            p = _up.urlparse(url)
            if p.scheme != "http" or p.hostname != "127.0.0.1":
                return {"status": 0, "content_type": "", "body": None}
            try:
                port = p.port
            except Exception:
                return {"status": 0, "content_type": "", "body": None}
            if port in (9119, 4096):
                return {"status": 0, "content_type": "", "body": None}
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
            conn = _hc.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("GET", path, headers={"Accept": "application/json"})
                resp = conn.getresponse()
                status = resp.status
                ctype = resp.getheader("Content-Type") or ""
                raw = resp.read(1048576)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            try:
                body = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                body = raw.decode("utf-8", "replace")
            return {"status": status, "content_type": ctype, "body": body}
        except Exception:
            return {"status": 0, "content_type": "", "body": None}


def _make_live_host():
    return LiveProofHost()


def _parse_live_records_ports(args):
    records = []
    ports = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--prep" and i + 1 < len(args):
            cur = {"prep_path": args[i + 1]}
            records.append(cur)
            i += 2
        elif a == "--image" and i + 1 < len(args):
            if not records:
                cur = {}
                records.append(cur)
            records[-1]["image_path"] = args[i + 1]
            i += 2
        elif a == "--expected-sha" and i + 1 < len(args):
            if not records:
                cur = {}
                records.append(cur)
            records[-1]["expected_sha256"] = args[i + 1]
            i += 2
        elif a == "--kind" and i + 1 < len(args):
            if not records:
                cur = {}
                records.append(cur)
            records[-1]["kind"] = args[i + 1]
            i += 2
        elif a == "--port" and i + 1 < len(args):
            try:
                pval = int(args[i + 1])
            except Exception:
                pval = args[i + 1]
            if records and "kind" in records[-1]:
                ports[records[-1]["kind"]] = pval
            else:
                ports[f"port{len(ports)}"] = pval
            i += 2
        elif a == "--execute-live":
            i += 1
        else:
            i += 1
    return records, ports


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("usage: operator_proof plan|apply|recover", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "plan":
        # minimal CLI: plan [--prep P --image I --expected-sha S --kind K --port N]... [--manifest-out O]
        records = []
        ports = {}
        manifest_out = None
        i = 1
        cur = {}
        while i < len(argv):
            a = argv[i]
            if a == "--prep" and i + 1 < len(argv):
                if cur:
                    pass
                cur = {"prep_path": argv[i + 1]}
                records.append(cur)
                i += 2
            elif a == "--image" and i + 1 < len(argv):
                if not records:
                    cur = {}
                    records.append(cur)
                records[-1]["image_path"] = argv[i + 1]
                i += 2
            elif a == "--expected-sha" and i + 1 < len(argv):
                if not records:
                    cur = {}
                    records.append(cur)
                records[-1]["expected_sha256"] = argv[i + 1]
                i += 2
            elif a == "--kind" and i + 1 < len(argv):
                if not records:
                    cur = {}
                    records.append(cur)
                records[-1]["kind"] = argv[i + 1]
                i += 2
            elif a == "--port" and i + 1 < len(argv):
                # associate with last kind if known else generic
                try:
                    pval = int(argv[i + 1])
                except Exception:
                    pval = argv[i + 1]
                if records and "kind" in records[-1]:
                    ports[records[-1]["kind"]] = pval
                else:
                    ports[f"port{len(ports)}"] = pval
                i += 2
            elif a == "--manifest-out" and i + 1 < len(argv):
                manifest_out = argv[i + 1]
                i += 2
            else:
                i += 1
        # if no records supplied, return manifest-refused (still exit 0)
        if not records:
            m = {
                "status": "manifest-refused",
                "signed": False,
                "activation": "UNEXECUTED",
                "service_cutover": "NOT_AUTHORIZED",
                "kernel_immutable": False,
                "gates": _gates_unexecuted(),
                "images": [],
                "error": "no records",
            }
            print(json.dumps({"status": "manifest-refused", "manifest": m, "commands": []}, sort_keys=True, indent=2))
            return 0
        res = plan(records, ports, manifest_out)
        print(json.dumps(res, sort_keys=True, indent=2))
        return 0
    if cmd in ("apply", "recover"):
        if "--execute-live" not in argv:
            return 3
        try:
            euid = os.geteuid()
        except AttributeError:
            return 4
        if euid != 0:
            return 4
        ok, _why = _live_file_ok()
        if not ok:
            return 4
        host = _make_live_host()
        if cmd == "apply":
            records, ports = _parse_live_records_ports(argv[1:])
            res = apply(host, records, ports)
            print(json.dumps(res, sort_keys=True, indent=2))
            return 0 if res.get("status") == "applied" else 1
        else:
            mounts = []
            i = 1
            while i < len(argv):
                a = argv[i]
                if a == "--execute-live":
                    i += 1
                    continue
                if a == "--mount" and i + 1 < len(argv):
                    mounts.append(argv[i + 1])
                    i += 2
                    continue
                if a.startswith("-"):
                    i += 1
                    continue
                mounts.append(a)
                i += 1
            res = recover(host, mounts)
            print(json.dumps(res, sort_keys=True, indent=2))
            return 0 if res.get("status") in ("stopped", "not-mounted") else 1
    print("usage: operator_proof plan|apply|recover", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
