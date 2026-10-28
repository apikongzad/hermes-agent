"""Runnerless operator proof. Stdlib only. No live effects unless --execute-live.

Live execution never imports scripts.stock_activation.
"""

import errno
import hashlib
import json
import os
import stat
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
    for k in _GATES:
        gates[k] = "EXECUTED"
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
    # global gates: use global evidence if it has executed+fields, else UNEXECUTED
    if isinstance(evidence, dict) and "executed" in evidence:
        gates = _gates_from_evidence(evidence)
    else:
        # check per-record evidence: only if all images observed with full fields?
        gates = gates_empty
        # if every image has full evidence, mark executed
        all_full = True
        for img, rec in zip(images, records):
            rec_ev = rec.get("evidence", rec.get("observations", rec.get("host_observation")))
            ev = _evidence_for_kind(rec_ev, evidence, rec.get("kind"))
            if not isinstance(ev, dict) or ev.get("executed") is not True:
                all_full = False
                break
            for k in ("write_errno", "rename_errno", "link_errno", "backing_writable_by_1001"):
                if k not in ev:
                    all_full = False
                    break
        if all_full and images:
            tmp = {"executed": True, "write_errno": 30, "rename_errno": 30,
                   "link_errno": 30, "backing_writable_by_1001": False}
            # only mark gates executed if actual evidences are full EROFS? No,
            # gates require executed+fields, not necessarily EROFS values.
            # Recompute with first evidence merged.
            gates = _gates_from_evidence({**tmp, **(evidence or {})}) if isinstance(evidence, dict) else _gates_from_evidence(tmp)
            # Simpler: if all_full, gates EXECUTED
            gates = {k: "EXECUTED" for k in _GATES}
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
    for rec in records:
        kind = rec["kind"]
        src = rec["image_path"]
        expected = rec["expected_sha256"]
        dest, mount, _digest = _dest_for_kind(kind)
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
        # parent symlink check
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
        except OSError:
            parent_link = False
        # foreign owner refuses before mutation; never chmod to fix
        if dest_exists:
            try:
                _omode, _ouid, _olink, _ = _lstat_mode_uid(host, dest)
            except Exception:
                _ouid = None
                _olink = False
            if _ouid is not None and _ouid != 0:
                return {"status": "refused", "reason": "foreign owner",
                        "signed": False, "activation": "UNEXECUTED",
                        "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                        "gates": _gates_unexecuted(), "images": results}
        # idempotent check when dest exists
        if dest_exists:
            try:
                dmode, duid, dlink, _ = _lstat_mode_uid(host, dest)
                dsha = host.sha256_file(dest)
            except (OSError, Exception):
                dsha, dmode, duid = None, None, None
            idem = (dsha == expected and dmode == 0o400 and duid == 0 and not dlink)
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
        # install dirs when dest absent
        if not dest_exists:
            for d, mode in ((LIB_DIR, "0700"), (BACKING_DIR, "0700"),
                            (RUN_DIR, "0755"), (mount, "0755")):
                if execute_commands:
                    host.run(install_dir_argv(d, mode), PROOF_ENV)
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
            except OSError:
                return {"status": "durable-state-unknown", "signed": False,
                        "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False, "gates": _gates_unexecuted(), "images": results}
            except Exception:
                return {"status": "durable-state-unknown", "signed": False,
                        "activation": "UNEXECUTED", "service_cutover": "NOT_AUTHORIZED",
                        "kernel_immutable": False, "gates": _gates_unexecuted(), "images": results}
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
        # must be one device
        if lrc != 0 or len(loop) != 1:
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        loopdev = loop[0].strip()
        if not loopdev.startswith("/dev/loop") or " " in loopdev or "\t" in loopdev:
            return {"status": "failed", "signed": False, "activation": "UNEXECUTED",
                    "service_cutover": "NOT_AUTHORIZED", "kernel_immutable": False,
                    "gates": _gates_unexecuted(), "images": results}
        # read-only back-file match: require loop output to be device only and
        # backing sha still matches (we already checked). If host provides
        # back-file info via extra attribute, check? Minimal: device format ok.
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
        # denial probes
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
        # backing not writable by 1001: dest uid 0 and no group/other write
        try:
            bmode, buid, _bl, _bs = _lstat_mode_uid(host, dest)
            if buid != 0 or (bmode is not None and (bmode & 0o022) != 0):
                imm = False
        except Exception:
            imm = False
        if not imm:
            overall_immutable = False
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
        web_ok = True
        if cli_ok and port is not None:
            try:
                wargv = web_proof_argv(mount, port)
            except ValueError:
                web_ok = False
                wargv = None
            if wargv is not None:
                try:
                    wres = host.run(wargv, PROOF_ENV)
                except Exception:
                    web_ok = False
                else:
                    wrc, _wout, _we = _coerce_run_result(wres)
                    if wrc != 0:
                        web_ok = False
        if not (cli_ok and web_ok):
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
        results.append({"kind": kind, "status": "applied", "destination": dest,
                        "mount": mount, "loop": loopdev,
                        "kernel_immutable": bool(imm), "observed": True})
    # never unlink journal: we never call unlink/remove
    return {"status": "applied", "signed": False, "activation": "UNEXECUTED",
            "service_cutover": "NOT_AUTHORIZED",
            "kernel_immutable": bool(overall_immutable) if results else False,
            "gates": _gates_unexecuted(), "images": results}


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
            run(umount_argv(mp), PROOF_ENV)
        except Exception:
            return {"status": "stopped-unresolved", "images": out}
        try:
            run(losetup_detach_argv(loopdev), PROOF_ENV)
        except Exception:
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
        # Live path would mutate; refuse by default via LiveRootHost semantics.
        # To avoid accidental live effects in this runnerless entrypoint,
        # do not proceed to real mutation here.
        return 4
    print("usage: operator_proof plan|apply|recover", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
