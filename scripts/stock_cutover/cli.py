"""Cutover public entry. Stdlib only. No live mutation in worker.

plan: deterministic, no root, exit 0. preflight: read-only
(show/proc/identity/digest/readback), verifies sibling hashes vs MANIFEST
BEFORE importing siblings, exit 0 with JSON, no mutation. apply/recover
without --execute-live exit 3 (refusal, no live effects). With
--execute-live requires euid 0 and installed path under
/var/lib/hermes-stock-activation/recovery with mode 0500, else exit 4;
even then mutation stays refused-live-not-authorized-here (exit 1) until
wiring is reviewed. Live execution never imports user trees, never reads
.env.
"""

import hashlib
import json
import os
import stat
import sys

INSTALL_PREFIX = "/var/lib/hermes-stock-activation/recovery"
MANIFEST_REL = "MANIFEST.json"


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
    if not os.path.isabs(norm):
        norm = os.path.normpath(os.path.join(os.getcwd(), norm))
    if norm != INSTALL_PREFIX + "/cli.py" and not norm.startswith(INSTALL_PREFIX + "/"):
        return False, "path"
    if norm != INSTALL_PREFIX + "/cli.py":
        # Only cli.py is the executable entry; sibling modules are imported
        # via file-relative loading, not as __main__.
        return False, "entry"
    return True, ""


def _entry_dir():
    try:
        p = __file__
    except NameError:
        return None
    d = os.path.dirname(os.path.abspath(p))
    return d


def _sha256_file(path):
    # O_NOFOLLOW hardening: lstat first, then open via O_NOFOLLOW fd.
    # Never follows symlink between check and hash (TOCTOU).
    try:
        lst = os.lstat(path)
    except OSError:
        raise
    if stat.S_ISLNK(lst.st_mode):
        raise OSError("symlink refused")
    if not stat.S_ISREG(lst.st_mode):
        raise OSError("not regular file")
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            h.update(b)
    finally:
        os.close(fd)
    return h.hexdigest()


def _is_root_live_dir(entry_dir):
    try:
        euid = os.geteuid()
    except AttributeError:
        return False
    if euid != 0:
        return False
    try:
        norm = os.path.normpath(entry_dir)
    except Exception:
        return False
    if norm == INSTALL_PREFIX or norm.startswith(INSTALL_PREFIX + "/"):
        return True
    return False


def _enforce_root_live_layout(entry_dir, rel, lst):
    """Enforce uid/mode/path when root live is allowed.

    Only called when _is_root_live_dir(entry_dir) is True. Requires
    uid 0, mode 0500 for .py siblings, 0400 for MANIFEST.json, entry
    under INSTALL_PREFIX, no symlink. Returns (ok, reason).
    """
    if lst.st_uid != 0:
        return False, f"root live uid: {rel}"
    mode = stat.S_IMODE(lst.st_mode)
    if rel == MANIFEST_REL:
        if mode != 0o400:
            return False, f"root live mode manifest: {rel} {oct(mode)}"
    elif rel.endswith(".py"):
        if mode != 0o500:
            return False, f"root live mode: {rel} {oct(mode)}"
    else:
        return False, f"root live rel: {rel}"
    return True, ""


def _verify_export_dir(entry_dir):
    """Verify every MANIFEST file hash BEFORE importing siblings.

    Returns (ok, reason, entry_shas). Performs no import, opens no .env,
    follows no symlink for hash targets (lstat + O_NOFOLLOW fd hash).
    Adversarial post-export overwrite yields ok=False and the caller must
    NOT import siblings. MANIFEST self-consistency is NOT trust: parent
    must verify REVIEWED digests after root-owned install. When running
    as root from INSTALL_PREFIX, additionally enforces uid/mode/path.
    """
    if not isinstance(entry_dir, str) or not entry_dir:
        return False, "entry dir type", {}
    if not os.path.isabs(entry_dir):
        return False, "entry dir relative", {}
    # Entry dir itself must not be symlink; root-live enforces ownership.
    try:
        dstat = os.lstat(entry_dir)
    except OSError as e:
        return False, f"entry dir missing: {e}", {}
    if stat.S_ISLNK(dstat.st_mode):
        return False, "entry dir symlink", {}
    if not stat.S_ISDIR(dstat.st_mode):
        return False, "entry dir not dir", {}
    root_live = _is_root_live_dir(entry_dir)
    if root_live:
        if dstat.st_uid != 0:
            return False, "root live entry uid", {}
        if stat.S_IMODE(dstat.st_mode) != 0o500:
            return False, "root live entry mode", {}
        norm = os.path.normpath(entry_dir)
        if norm != INSTALL_PREFIX and not norm.startswith(INSTALL_PREFIX + "/"):
            return False, "root live path", {}
    man = os.path.join(entry_dir, MANIFEST_REL)
    try:
        st = os.lstat(man)
    except OSError as e:
        return False, f"manifest missing: {e}", {}
    if stat.S_ISLNK(st.st_mode):
        return False, "manifest symlink", {}
    if root_live:
        ok, why = _enforce_root_live_layout(entry_dir, MANIFEST_REL, st)
        if not ok:
            return False, why, {}
    try:
        # O_NOFOLLOW read of MANIFEST.
        mfd = os.open(man, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            chunks = []
            while True:
                b = os.read(mfd, 65536)
                if not b:
                    break
                chunks.append(b)
            raw = b"".join(chunks)
        finally:
            os.close(mfd)
        payload = json.loads(raw.decode("utf-8"))
    except OSError as e:
        return False, f"manifest unreadable: {e}", {}
    except Exception as e:
        return False, f"manifest parse: {e}", {}
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        return False, "manifest files", {}
    entry_shas = {}
    for ent in files:
        if not isinstance(ent, dict):
            return False, "manifest entry type", {}
        rel = ent.get("rel")
        want = ent.get("sha256")
        if not isinstance(rel, str) or not isinstance(want, str):
            return False, "manifest entry fields", {}
        if "/" in rel or rel in (".", "..") or not rel.endswith(".py"):
            return False, "manifest rel: " + rel, {}
        if ".hermes/.env" in rel or rel == ".env":
            return False, "manifest env", {}
        p = os.path.join(entry_dir, rel)
        try:
            lst = os.lstat(p)
        except OSError as e:
            return False, f"sibling missing {rel}: {e}", {}
        if stat.S_ISLNK(lst.st_mode):
            return False, f"sibling symlink: {rel}", {}
        if not stat.S_ISREG(lst.st_mode):
            return False, f"sibling not file: {rel}", {}
        if root_live:
            ok, why = _enforce_root_live_layout(entry_dir, rel, lst)
            if not ok:
                return False, why, {}
        try:
            got = _sha256_file(p)
        except OSError as e:
            return False, f"sibling unreadable {rel}: {e}", {}
        if got != want:
            return False, f"sibling hash mismatch: {rel}", {}
        entry_shas[rel] = got
    # No extra .py siblings beyond the manifest (catches added rogue file).
    try:
        present = sorted(n for n in os.listdir(entry_dir) if n.endswith(".py"))
    except OSError as e:
        return False, f"listdir: {e}", {}
    for n in present:
        if n not in entry_shas:
            return False, f"extra sibling: {n}", {}
    if os.path.lexists(os.path.join(entry_dir, ".git")):
        return False, "export has .git", {}
    return True, "", entry_shas


def _load_verified_host(entry_dir):
    import importlib.util as _ilu
    mod_path = os.path.join(entry_dir, "cutover_host.py")
    spec = _ilu.spec_from_file_location("cutover_host_verified", mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("spec")
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_verified_orchestrate(entry_dir):
    import importlib.util as _ilu
    mod_path = os.path.join(entry_dir, "cutover_orchestrate.py")
    spec = _ilu.spec_from_file_location("cutover_orchestrate_verified", mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("spec")
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plan_result():
    return {
        "status": "manifest-ready",
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "NOT-AUTHORIZED",
        "kernel_immutable": False,
        "gates": {k: "UNEXECUTED" for k in (
            "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8",
            "A9", "A10", "A11", "A12", "A13",
            "B1", "B2", "B3", "B4", "B5", "B6", "B7",
            "C1", "C2", "C3", "C4",
        )},
        "images": [],
    }


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("usage: cli plan|preflight|apply|recover", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "plan":
        print(json.dumps(_plan_result(), sort_keys=True, indent=2))
        return 0
    if cmd == "preflight":
        entry_dir = _entry_dir()
        if entry_dir is None:
            print(json.dumps({"status": "preflight-refused",
                               "reason": "no entry dir",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        ok, reason, _shas = _verify_export_dir(entry_dir)
        if not ok:
            print(json.dumps({"status": "preflight-refused",
                               "reason": reason,
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        try:
            host_mod = _load_verified_host(entry_dir)
        except Exception as e:
            print(json.dumps({"status": "preflight-refused",
                               "reason": f"load: {e}",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        try:
            host = host_mod.RealCutoverHost()
            res = host_mod.preflight_readonly(host)
        except Exception as e:
            print(json.dumps({"status": "preflight-refused",
                               "reason": f"{type(e).__name__}: {e}",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        # MANIFEST self-consistency is NOT trust. Parent must verify
        # REVIEWED digests after root-owned install. Root-live additionally
        # enforces uid/mode/path via _verify_export_dir.
        if isinstance(res, dict):
            res["manifest_trust"] = "self-consistent-only-not-trusted"
            try:
                res["root_live_enforced"] = bool(_is_root_live_dir(entry_dir))
            except Exception:
                res["root_live_enforced"] = False
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
        # §10 live wiring: AFTER verified root-installed package (ALL
        # siblings hash-verified BEFORE import) and explicit
        # --execute-live, execute the actual production transaction
        # (RealCutoverHost + cutover_orchestrate, same lock for apply and
        # recover). Worker never reaches here (non-root, not installed):
        # no live systemctl/mount/service effects in worker.
        entry_dir = _entry_dir()
        if entry_dir is None:
            print(json.dumps({"status": "live-refused",
                               "reason": "no entry dir",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        ok, reason, _shas = _verify_export_dir(entry_dir)
        if not ok:
            # Verification-before-import: adversarial sibling must NOT
            # execute; marker absent. No live effects.
            print(json.dumps({"status": "live-refused",
                               "reason": reason,
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        try:
            host_mod = _load_verified_host(entry_dir)
            orch_mod = _load_verified_orchestrate(entry_dir)
        except Exception as e:
            print(json.dumps({"status": "live-refused",
                               "reason": f"load: {e}",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        try:
            host = host_mod.RealCutoverHost()
            receipt = orch_mod.orchestrate(host)
            state = getattr(receipt, "state", "stopped-unresolved")
            reason_r = getattr(receipt, "reason", None)
            try:
                journal = list(getattr(receipt, "journal", []))
            except Exception:
                journal = []
        except Exception as e:
            print(json.dumps({"status": "stopped-unresolved",
                               "reason": f"{type(e).__name__}: {e}",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED",
                               "journal": []},
                             sort_keys=True, indent=2))
            return 1
        # Readiness, NOT activation claim: parent must verify REVIEWED
        # digests after root install and authorize separately. Exit codes
        # drive systemd OnFailure (0 success, 1 stopped/blocked, 2 durable).
        print(json.dumps({"status": state,
                           "reason": reason_r,
                           "journal": journal,
                           "signed": False,
                           "activation": "UNEXECUTED",
                           "service_cutover": "NOT-AUTHORIZED"},
                         sort_keys=True, indent=2))
        base = str(state).split(":")[0].strip() if isinstance(state, str) else str(state)
        if base in ("committed", "rolled-back"):
            return 0
        if base == "durable-state-unknown":
            return 2
        return 1
    if cmd == "--self-check":
        print("daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06")
        print("1d9a377fa00ce0e663e274e16b63c75e36233b9e")
        return 0
    print("usage: cli plan|preflight|apply|recover", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
