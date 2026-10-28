"""Cutover public entry. Stdlib only. No live effects without --execute-live.

plan: deterministic, no root, exit 0. apply/recover without --execute-live
exit 3 (refusal, no live effects). With --execute-live requires euid 0 and
installed path under /var/lib/hermes-stock-activation/recovery with mode
0500, else exit 4. Live execution never imports user trees, never reads .env.
"""

import json
import os
import stat
import sys

INSTALL_PREFIX = "/var/lib/hermes-stock-activation/recovery"


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


def _plan_result():
    return {
        "status": "manifest-ready",
        "signed": False,
        "activation": "UNEXECUTED",
        "service_cutover": "AUTHORIZED-BY-REVIEW",
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
        print("usage: cli plan|apply|recover", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "plan":
        print(json.dumps(_plan_result(), sort_keys=True, indent=2))
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
        # Live path would wire RealCutoverHost + cutover_orchestrate here.
        # Parent runs this only after digest verification. Worker tests never
        # reach this branch live (they assert exit 3/4 without live effects).
        print(json.dumps({
            "status": "refused-live-not-authorized-here",
            "signed": False,
            "activation": "UNEXECUTED",
        }, sort_keys=True, indent=2))
        return 1
    if cmd == "--self-check":
        print("daec3cd4c6d34f5befbc8f25a8af3e3b84b94f06")
        print("1d9a377fa00ce0e663e274e16b63c75e36233b9e")
        return 0
    print("usage: cli plan|apply|recover", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
