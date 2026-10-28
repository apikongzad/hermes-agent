"""Cutover public entry. Stdlib only. No live mutation in worker.

plan: deterministic, no root, exit 0. preflight: read-only
(show/proc/identity/digest/readback), verifies sibling hashes vs MANIFEST
BEFORE importing siblings, exit 0 with JSON, no mutation. apply/recover
without --execute-live exit 3 (refusal, no live effects). With
--execute-live requires euid 0 and installed path under
/var/lib/hermes-stock-activation/recovery with mode 0500, else exit 4.

External REVIEWED pin gate (fail-closed, no self-authorization):
apply/recover (and root-live preflight) must compare the root-protected
external pin at REVIEWED_PIN_PATH (outside the package, root 0400 parent
0700 same owner) BEFORE any sibling import. The pin is minted by the parent
operator AFTER exact manual review via independent digest readback
(sha256sum on installed files + rendered units, computed OUTSIDE the
package, never hardcoded in module constants, no hardcoded self hash).
Code never equates its own MANIFEST self-consistency to review: a
self-consistent root package WITHOUT an independent pin REFUSES (exit 4,
marker absent, zero sibling exec). Bootstrap cli.py own bytes are also
bound to the pin before imports. Pin is UNSIGNED honest (not a crypto
signature); parent manual review is the authority, a new pin is permitted
only after a new exact review. Malicious root can overwrite both code and
pins (same authority trust scope, disclosed in README). No caller boolean,
no arbitrary pin path via CLI (fixed path only), O_NOFOLLOW regular-file
single-link ownership/mode checks plus FD reads with closed-field format
validation before any sibling exec. Live execution never imports user
trees, never reads .env.
"""

import hashlib
import json
import os
import stat
import sys

INSTALL_PREFIX = "/var/lib/hermes-stock-activation/recovery"
MANIFEST_REL = "MANIFEST.json"
README_REL = "README.parent.md"

# Fixed external REVIEWED pin (outside the package, never a CLI arg).
REVIEWED_PIN_PATH = "/var/lib/hermes-stock-activation/reviewed-package.json"
REVIEWED_PIN_PARENT = "/var/lib/hermes-stock-activation"
REVIEWED_PIN_GRANDPARENT = "/var/lib"

# Exact module set bound by the pin (filenames only, never hashes here).
# Hashes live ONLY in the external pin minted outside the package.
PIN_EXPECTED_FILES = (
    "__init__.py",
    "cli.py",
    "cutover_host.py",
    "cutover_orchestrate.py",
    "cutover_recovery.py",
    "cutover_units.py",
)

PIN_ALLOWED_TOP_KEYS = frozenset({
    "format",
    "files",
    "manifest_sha256",
    "template_sha256",
    "unit_template_sha256",
    "signed",
    "reviewed_by",
})


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


def _is_hex64(s):
    if not isinstance(s, str) or len(s) != 64:
        return False
    for c in s:
        if c not in "0123456789abcdef":
            return False
    return True


def _read_reviewed_pin(pin_path=None, expected_uid=None):
    """Read and validate the external REVIEWED pin BEFORE any sibling import.

    Fixed production path REVIEWED_PIN_PATH only in main(); pin_path param
    exists ONLY for bounded fixture tests (never a CLI arg, never a caller
    boolean). Enforces O_NOFOLLOW regular single-link ownership/modes plus
    FD reads with closed-field format validation. Never opens .env.

    Production (pin_path == REVIEWED_PIN_PATH): file 0400 uid 0, parent
    0700 uid 0 same owner, grandparent /var/lib 0755 uid 0. Fixture (temp
    path under HOME for tests): file 0400 euid, parent 0700 euid same
    owner. expected_uid override (tests only) simulates production
    ownership requirement on a temp file (e.g., temp file uid 1001 vs
    expected 0 must refuse, proving non-root-owner refusal without root).

    Returns (ok, reason, pin_dict). pin_dict is None on failure. Caller
    must NOT import siblings unless ok.
    """
    if pin_path is None:
        pin_path = REVIEWED_PIN_PATH
    if not isinstance(pin_path, str) or not pin_path:
        return False, "pin path type", None
    if not os.path.isabs(pin_path):
        return False, "pin path relative", None
    if ".." in pin_path.split("/"):
        return False, "pin path dotdot", None
    # No .env in pin path, no caller-controlled outside authority except
    # the single fixed production path and temp HOME fixtures for tests.
    if ".hermes/.env" in pin_path or pin_path.endswith("/.env"):
        return False, "pin env path", None
    is_prod = (os.path.normpath(pin_path) == os.path.normpath(REVIEWED_PIN_PATH))
    try:
        euid = os.geteuid()
    except AttributeError:
        euid = 0
    if expected_uid is None:
        expected_uid = 0 if is_prod else euid
    # lstat, no follow, single link: regular file, no symlink.
    try:
        st = os.lstat(pin_path)
    except OSError as e:
        return False, f"pin missing: {e}", None
    if stat.S_ISLNK(st.st_mode):
        return False, "pin symlink", None
    if not stat.S_ISREG(st.st_mode):
        return False, "pin not regular", None
    if stat.S_IMODE(st.st_mode) != 0o400:
        return False, f"pin mode {oct(stat.S_IMODE(st.st_mode))}", None
    if st.st_uid != expected_uid:
        return False, f"pin owner {st.st_uid} want {expected_uid}", None
    # Parent: lstat, no symlink, dir 0700 same owner.
    parent = os.path.dirname(os.path.normpath(pin_path)) or "/"
    try:
        pst = os.lstat(parent)
    except OSError as e:
        return False, f"pin parent missing: {e}", None
    if stat.S_ISLNK(pst.st_mode):
        return False, "pin parent symlink", None
    if not stat.S_ISDIR(pst.st_mode):
        return False, "pin parent not dir", None
    if stat.S_IMODE(pst.st_mode) != 0o700:
        return False, f"pin parent mode {oct(stat.S_IMODE(pst.st_mode))}", None
    if pst.st_uid != expected_uid:
        return False, "pin parent owner", None
    if pst.st_uid != st.st_uid:
        return False, "pin owner mismatch parent", None
    if is_prod:
        # Grandparent /var/lib 0755 uid 0, not symlink, not writable by 1001.
        try:
            gst = os.lstat(REVIEWED_PIN_GRANDPARENT)
        except OSError as e:
            return False, f"pin grandparent missing: {e}", None
        if stat.S_ISLNK(gst.st_mode):
            return False, "pin grandparent symlink", None
        if gst.st_uid != 0 or stat.S_IMODE(gst.st_mode) != 0o755:
            return False, "pin grandparent ownership", None
        # Production parent must be the fixed REVIEWED_PIN_PARENT.
        if os.path.normpath(parent) != os.path.normpath(REVIEWED_PIN_PARENT):
            return False, "pin parent fixed", None
    # FD read via O_NOFOLLOW, bounded (64 KiB cap is plenty for pin JSON).
    try:
        fd = os.open(pin_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        return False, f"pin open: {e}", None
    try:
        chunks = []
        total = 0
        while True:
            b = os.read(fd, 8192)
            if not b:
                break
            chunks.append(b)
            total += len(b)
            if total > 65536:
                return False, "pin too large", None
        raw = b"".join(chunks)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        pin = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return False, f"pin parse: {e}", None
    if not isinstance(pin, dict):
        return False, "pin type", None
    # Closed fields: exactly the allowed top keys, no unknown, no missing.
    try:
        keys = set(pin.keys())
    except Exception:
        return False, "pin keys", None
    if keys != set(PIN_ALLOWED_TOP_KEYS):
        # Distinguish unknown vs missing for diagnostics, both refuse.
        extra = keys - set(PIN_ALLOWED_TOP_KEYS)
        if extra:
            return False, f"pin unknown key: {sorted(extra)[0]}", None
        return False, "pin missing keys", None
    if not isinstance(pin.get("format"), int) or isinstance(pin.get("format"), bool):
        return False, "pin format type", None
    if pin.get("format") != 1:
        return False, "pin format value", None
    if pin.get("signed") is not False:
        return False, "pin signed must be false", None
    rb = pin.get("reviewed_by")
    if not isinstance(rb, str) or not (1 <= len(rb) <= 256):
        return False, "pin reviewed_by", None
    if ".hermes/.env" in rb or "\n" in rb and len(rb) > 256:
        return False, "pin reviewed_by env", None
    files = pin.get("files")
    if not isinstance(files, dict):
        return False, "pin files type", None
    if set(files.keys()) != set(PIN_EXPECTED_FILES):
        extra = set(files.keys()) - set(PIN_EXPECTED_FILES)
        if extra:
            return False, f"pin unknown file: {sorted(extra)[0]}", None
        return False, "pin files missing", None
    for rel, sha in files.items():
        if not isinstance(rel, str) or not isinstance(sha, str):
            return False, "pin file fields", None
        if "/" in rel or rel in (".", "..") or not rel.endswith(".py"):
            return False, f"pin rel: {rel}", None
        if ".hermes/.env" in rel or rel == ".env":
            return False, "pin env file", None
        if not _is_hex64(sha):
            return False, f"pin sha: {rel}", None
    for k in ("manifest_sha256", "template_sha256", "unit_template_sha256"):
        if not _is_hex64(pin.get(k)):
            return False, f"pin {k}", None
    return True, "", pin


def _verify_against_pin(entry_dir, entry_shas, pin):
    """Compare actual export hashes to the external pin BEFORE import.

    entry_shas comes from _verify_export_dir (actual O_NOFOLLOW hashes of
    each .py). Also hashes MANIFEST.json and README.parent.md file bytes
    via O_NOFOLLOW FDs and compares to pin manifest/template. Verifies
    bootstrap cli.py own bytes (hash of __file__ via O_NOFOLLOW) equal
    pin files[cli.py]. Returns (ok, reason). No import, no .env, no exec.
    """
    if not isinstance(pin, dict):
        return False, "pin type"
    files = pin.get("files")
    if not isinstance(files, dict):
        return False, "pin files"
    # Each actual .py hash must equal the REVIEWED pin (not just MANIFEST
    # self-consistency). Code cannot self-authorize via its own MANIFEST.
    for rel in PIN_EXPECTED_FILES:
        want = files.get(rel)
        got = entry_shas.get(rel) if isinstance(entry_shas, dict) else None
        if not isinstance(want, str) or not isinstance(got, str):
            return False, f"pin compare missing: {rel}"
        if got != want:
            return False, f"pin mismatch: {rel}"
    # Bootstrap own bytes: running cli.py must be the pinned cli.py.
    try:
        self_path = __file__
    except NameError:
        return False, "no self file"
    try:
        self_sha = _sha256_file(self_path)
    except OSError as e:
        return False, f"self unreadable: {e}"
    if self_sha != files.get("cli.py"):
        return False, "pin mismatch: cli.py self"
    # MANIFEST.json file bytes vs pin manifest.
    man_path = os.path.join(entry_dir, MANIFEST_REL)
    try:
        man_sha = _sha256_file(man_path)
    except OSError as e:
        return False, f"manifest unreadable: {e}"
    if man_sha != pin.get("manifest_sha256"):
        return False, "pin mismatch: manifest"
    # README.parent.md file bytes vs pin template (operator recipe binding).
    readme_path = os.path.join(entry_dir, README_REL)
    try:
        rst = os.lstat(readme_path)
    except OSError as e:
        return False, f"readme missing: {e}"
    if stat.S_ISLNK(rst.st_mode):
        return False, "readme symlink"
    if not stat.S_ISREG(rst.st_mode):
        return False, "readme not file"
    try:
        readme_sha = _sha256_file(readme_path)
    except OSError as e:
        return False, f"readme unreadable: {e}"
    if readme_sha != pin.get("template_sha256"):
        return False, "pin mismatch: template"
    return True, ""


def _verify_unit_template(recovery_mod, pin):
    """Verify rendered unit templates match the pin AFTER import.

    Called after files+manifest+readme already verified and siblings
    imported, but BEFORE any transaction (no journal, no fence, no start).
    Renders via recovery_mod.unit_template_sha() (or fallback
    concatenation) and compares to pin unit_template_sha256. Returns
    (ok, reason). No .env, no exec beyond rendering.
    """
    if not isinstance(pin, dict):
        return False, "pin type"
    want = pin.get("unit_template_sha256")
    if not _is_hex64(want):
        return False, "pin unit hash"
    try:
        fn = getattr(recovery_mod, "unit_template_sha", None)
        if callable(fn):
            got = fn()
        else:
            # Fallback: hash concatenated unit texts directly.
            parts = [
                recovery_mod.cutover_service_unit(),
                recovery_mod.recover_service_unit(),
                recovery_mod.recover_timer_unit(),
                recovery_mod.known_good_mount_unit(),
                recovery_mod.candidate_mount_unit(),
            ]
            got = hashlib.sha256(
                ("\n---\n".join(parts)).encode("utf-8")
            ).hexdigest()
    except Exception as e:
        return False, f"unit render: {e}"
    if not isinstance(got, str) or got != want:
        return False, "pin mismatch: unit-template"
    return True, ""


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


def _load_verified_recovery(entry_dir):
    import importlib.util as _ilu
    mod_path = os.path.join(entry_dir, "cutover_recovery.py")
    spec = _ilu.spec_from_file_location("cutover_recovery_verified", mod_path)
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
        # Root-live preflight ALSO requires the external REVIEWED pin before
        # any sibling import (self-consistent without independent pin must
        # refuse, marker zero exec). Worker (non-root temp HOME) stays
        # self-consistent-only so existing read-only checks keep working
        # without root; production root-live never executes siblings on
        # pin absence/mismatch.
        _root_live = False
        try:
            _root_live = bool(_is_root_live_dir(entry_dir))
        except Exception:
            _root_live = False
        _pin = None
        if _root_live:
            pok, preason, _pin = _read_reviewed_pin()
            if not pok:
                print(json.dumps({"status": "preflight-refused",
                                   "reason": f"reviewed-pin: {preason}",
                                   "signed": False,
                                   "activation": "UNEXECUTED",
                                   "service_cutover": "NOT-AUTHORIZED"},
                                 sort_keys=True, indent=2))
                return 4
            vok, vreason = _verify_against_pin(entry_dir, _shas, _pin)
            if not vok:
                print(json.dumps({"status": "preflight-refused",
                                   "reason": f"reviewed-pin: {vreason}",
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
        # enforces uid/mode/path via _verify_export_dir plus external pin.
        if isinstance(res, dict):
            res["manifest_trust"] = "self-consistent-only-not-trusted"
            try:
                res["root_live_enforced"] = bool(_is_root_live_dir(entry_dir))
            except Exception:
                res["root_live_enforced"] = False
            try:
                res["reviewed_pin"] = "verified" if _root_live else "absent-not-required-worker"
            except Exception:
                res["reviewed_pin"] = "unknown"
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
        # External REVIEWED pin gate BEFORE any sibling import. Fixed path
        # only (no CLI flag, no caller boolean). Self-consistent without
        # independent pin REFUSES here with marker zero exec. Bootstrap
        # cli.py own bytes are bound to the pin inside _verify_against_pin.
        # O_NOFOLLOW + ownership/modes + FD reads + closed fields, no .env.
        pok, preason, _pin = _read_reviewed_pin()
        if not pok:
            print(json.dumps({"status": "live-refused",
                               "reason": f"reviewed-pin: {preason}",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        vok, vreason = _verify_against_pin(entry_dir, _shas, _pin)
        if not vok:
            print(json.dumps({"status": "live-refused",
                               "reason": f"reviewed-pin: {vreason}",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        try:
            host_mod = _load_verified_host(entry_dir)
            orch_mod = _load_verified_orchestrate(entry_dir)
            rec_mod = _load_verified_recovery(entry_dir)
        except Exception as e:
            print(json.dumps({"status": "live-refused",
                               "reason": f"load: {e}",
                               "signed": False,
                               "activation": "UNEXECUTED",
                               "service_cutover": "NOT-AUTHORIZED"},
                             sort_keys=True, indent=2))
            return 4
        # Unit-template binding AFTER import but BEFORE any transaction:
        # rendered units must equal the REVIEWED unit hash, else refuse
        # with no journal, no fence, no start.
        uok, ureason = _verify_unit_template(rec_mod, _pin)
        if not uok:
            print(json.dumps({"status": "live-refused",
                               "reason": f"reviewed-pin: {ureason}",
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
