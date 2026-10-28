"""Unprivileged prep export. Preparation only, never activation.

Stages known-good and candidate closures into a caller-supplied user-owned
stage directory and writes SquashFS images there. No live effects.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess


_GIT_BIN = "/usr/bin/git"
_TAR_BIN = "/usr/bin/tar"
_RSYNC_BIN = "/usr/bin/rsync"
_MKSQUASHFS_BIN = "/usr/bin/mksquashfs"
_UNSQUASHFS_BIN = "/usr/bin/unsquashfs"

_KNOWN_GOOD_MOUNT = "/run/hermes-stock-activation/known-good-snap"
_CANDIDATE_MOUNT = "/run/hermes-stock-activation/candidate-snap"

_PYTHON_LINK_TARGET = "../../interpreter/bin/python3.14"
_PYTHON_LINK_NAMES = ("python", "python3", "python3.14")

_FINDER_BASENAME = "__editable___hermes_agent_0_0_0_finder.py"
_DIRECT_URL_PARENT = "hermes_agent-0.0.0.dist-info"
_DIRECT_URL_BASENAME = "direct_url.json"

_BAD_NONCES = {
    "0" * 32,
    "1" * 32,
    "f" * 32,
    "a" * 32,
    "0123456789abcdef0123456789abcdef",
    "fedcba9876543210fedcba9876543210",
    "deadbeefdeadbeefdeadbeefdeadbeef",
    "cafebabecafebabecafebabecafebabe",
}


def _is_under(path, prefix):
    if path == prefix:
        return True
    return path.startswith(prefix + "/")


def _is_predictable_nonce(nonce):
    if not isinstance(nonce, str):
        return True
    if len(nonce) != 32:
        return True
    low = nonce.lower()
    for c in low:
        if c not in "0123456789abcdef":
            return True
    if len(set(low)) < 5:
        return True
    if low in _BAD_NONCES:
        return True
    return False


def _generate_nonce():
    with open("/dev/urandom", "rb") as f:
        data = f.read(16)
    if len(data) != 16:
        raise RuntimeError("urandom short")
    nonce = data.hex()
    if _is_predictable_nonce(nonce):
        # Extremely unlikely; retry once with fresh bytes.
        with open("/dev/urandom", "rb") as f:
            data = f.read(16)
        if len(data) != 16:
            raise RuntimeError("urandom short")
        nonce = data.hex()
        if _is_predictable_nonce(nonce):
            raise RuntimeError("predictable nonce")
    return nonce


def _git_archive_argv(repo, sha, output):
    return [
        _GIT_BIN,
        "-C",
        repo,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "archive",
        "--format=tar",
        "--output=" + output,
        sha,
    ]


def _tar_extract_argv(staging_source, tar_path):
    return [
        _TAR_BIN,
        "-C",
        staging_source,
        "--no-same-owner",
        "--no-same-permissions",
        "-xf",
        tar_path,
    ]


def _rsync_argv(src, dst):
    s = src.rstrip("/") + "/"
    d = dst.rstrip("/") + "/"
    return [
        _RSYNC_BIN,
        "-a",
        "--fsync",
        "--numeric-ids",
        "--exclude=.git",
        "--exclude=.env",
        "--exclude=.envrc",
        "--exclude=__pycache__",
        "--exclude=*.pyc",
        "--exclude=.leases",
        "--exclude=auth.json",
        "--exclude=config.yaml",
        "--",
        s,
        d,
    ]


def _mksquashfs_argv(staged, image_tmp):
    return [
        _MKSQUASHFS_BIN,
        staged,
        image_tmp,
        "-comp",
        "xz",
        "-b",
        "131072",
        "-reproducible",
        "-mkfs-time",
        "0",
        "-all-root",
        "-no-xattrs",
        "-no-hardlinks",
        "-no-exports",
        "-no-recovery",
        "-no-progress",
        "-noappend",
    ]


def _unsquashfs_argv(image, dest):
    return [
        _UNSQUASHFS_BIN,
        "-no-xattrs",
        "-d",
        dest,
        image,
    ]


def _run_cmd(argv, env, runner):
    if runner is None:
        return subprocess.run(
            argv, shell=False, env=env, capture_output=True, check=False
        )
    if hasattr(runner, "run") and callable(runner.run):
        try:
            return runner.run(argv, env)
        except TypeError:
            return runner.run(argv)
    # callable runner
    try:
        return runner(argv, env)
    except TypeError:
        return runner(argv)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _refused(kind, *, archive_sha256=None, web_dist="omitted-unverified",
             design_absolute_gate="clean", residual=None):
    return {
        "status": "prep-refused",
        "success": False,
        "kind": kind,
        "image_path": None,
        "image_sha256": None,
        "image_bytes": None,
        "manifest_sha256": None,
        "manifest": "",
        "archive_sha256": archive_sha256,
        "digest_file": None,
        "signed": False,
        "live_published": False,
        "kernel_immutable": False,
        "mount_executed": False,
        "activation": "UNEXECUTED",
        "web_dist": web_dist,
        "design_absolute_gate": design_absolute_gate,
        "residual_embedded_paths": list(residual) if residual else [],
        "rollback_clean": True,
        "source_sha": None,
    }


def _durable_unknown(kind, *, archive_sha256=None, error=None):
    return {
        "status": "durable-state-unknown",
        "success": False,
        "kind": kind,
        "image_path": None,
        "image_sha256": None,
        "image_bytes": None,
        "manifest_sha256": None,
        "manifest": "",
        "archive_sha256": archive_sha256,
        "digest_file": None,
        "signed": False,
        "live_published": False,
        "kernel_immutable": False,
        "mount_executed": False,
        "activation": "UNEXECUTED",
        "web_dist": "omitted-unverified",
        "design_absolute_gate": "clean",
        "residual_embedded_paths": [],
        "rollback_clean": False,
        "source_sha": None,
        "error": str(error) if error is not None else "",
    }


def _validate_stage_root(stage_root, extra_forbidden):
    # Returns (norm, error_string_or_None)
    if not isinstance(stage_root, str):
        return None, "stage type"
    if not os.path.isabs(stage_root):
        return None, "stage not absolute"
    norm = os.path.normpath(stage_root)
    try:
        st = os.lstat(norm)
    except FileNotFoundError:
        return None, "stage missing"
    except NotADirectoryError:
        return None, "stage not dir"
    except OSError as e:
        return None, f"stage lstat: {e}"
    if stat.S_ISLNK(st.st_mode):
        return None, "stage symlink"
    if not stat.S_ISDIR(st.st_mode):
        return None, "stage not dir"
    try:
        if st.st_uid != os.getuid():
            return None, "stage owner"
    except Exception as e:
        return None, f"stage owner check: {e}"
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o022:
        return None, "stage writable"
    for forb in extra_forbidden:
        if forb is None:
            continue
        if not isinstance(forb, str) or forb == "":
            continue
        fnorm = os.path.normpath(forb)
        if norm == fnorm or _is_under(norm, fnorm):
            return None, "stage protected"
    # Fixed protected prefixes.
    for prefix in (
        "/var/lib/hermes-stock-activation",
        "/run/hermes-stock-activation",
        "/home/ubuntu/.hermes/hermes-agent",
        "/home/ubuntu/.hermes/runtime/stock-candidates",
        "/home/ubuntu/.hermes/runtime/cutover-generations",
        "/home/ubuntu/.hermes/installs",
        "/home/ubuntu/.hermes/tools",
    ):
        if norm == prefix or _is_under(norm, prefix):
            return None, "stage protected"
    return norm, None


def _deny_tree(root):
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Check dir components for special files.
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode):
                raise RuntimeError("fifo/socket")
            if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                raise RuntimeError("device")
        rel_dir = os.path.relpath(dirpath, root)
        parts = [] if rel_dir == "." else rel_dir.split(os.sep)
        for comp in parts:
            if comp in (".git", ".env", ".envrc", "__pycache__", ".leases",
                        "state.db", "state.db-wal", "state.db-shm"):
                raise RuntimeError("denylist " + comp)
            if comp.endswith(".pyc"):
                raise RuntimeError("denylist pyc")
        for name in filenames:
            if name in ("state.db", "state.db-wal", "state.db-shm"):
                raise RuntimeError("denylist state")
            if name.endswith(".pyc"):
                raise RuntimeError("denylist pyc")
            if name in (".env", ".envrc", ".leases"):
                raise RuntimeError("denylist " + name)
            if name == ".git":
                raise RuntimeError("denylist .git")
        for name in dirnames:
            if name in (".git", ".env", ".envrc", "__pycache__", ".leases",
                        "state.db", "state.db-wal", "state.db-shm"):
                raise RuntimeError("denylist " + name)
            if name.endswith(".pyc"):
                raise RuntimeError("denylist pyc")


def _prune_user_sessions(staging_root):
    # Remove directories/files named "sessions" that are not under
    # site-packages or lib/python. Library sessions are preserved.
    for dirpath, dirnames, filenames in os.walk(staging_root, topdown=True, followlinks=False):
        for name in list(dirnames):
            if name != "sessions":
                continue
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                dirnames.remove(name)
                continue
            if not stat.S_ISDIR(st.st_mode):
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            rel = os.path.relpath(full, staging_root)
            if "site-packages" in rel or "lib/python" in rel:
                continue
            # User sessions dir: remove.
            shutil.rmtree(full, ignore_errors=False)
            dirnames.remove(name)
        for name in list(filenames):
            if name != "sessions":
                continue
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                # Symlink named sessions: handled in symlink phase; leave here.
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            rel = os.path.relpath(full, staging_root)
            if "site-packages" in rel or "lib/python" in rel:
                continue
            try:
                os.unlink(full)
            except FileNotFoundError:
                pass


def _handle_symlinks(staging_root, venv_bins):
    for dirpath, dirnames, filenames in os.walk(staging_root, topdown=True, followlinks=False):
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if not stat.S_ISLNK(st.st_mode):
                continue
            target = os.readlink(full)
            parent = os.path.dirname(full)
            is_python_name = (name in _PYTHON_LINK_NAMES) and (parent in venv_bins)
            if is_python_name:
                continue
            if os.path.isabs(target):
                raise RuntimeError("abs symlink")
            dest_norm = os.path.normpath(os.path.join(parent, target))
            sroot = os.path.normpath(staging_root)
            if dest_norm == sroot or _is_under(dest_norm, sroot):
                continue
            raise RuntimeError("outside symlink")


def _replace_python_links(venv_bins):
    for b in list(venv_bins):
        for n in _PYTHON_LINK_NAMES:
            link = os.path.join(b, n)
            try:
                st = os.lstat(link)
                is_link = stat.S_ISLNK(st.st_mode)
            except FileNotFoundError:
                is_link = False
            try:
                target_now = os.readlink(link) if is_link else None
            except OSError:
                target_now = None
            if target_now == _PYTHON_LINK_TARGET:
                continue
            if os.path.lexists(link):
                # Only replace regular files/symlinks, refuse special.
                try:
                    st2 = os.lstat(link)
                except FileNotFoundError:
                    pass
                else:
                    if not (stat.S_ISLNK(st2.st_mode) or stat.S_ISREG(st2.st_mode)):
                        raise RuntimeError("python link special")
                os.unlink(link)
            os.symlink(_PYTHON_LINK_TARGET, link)


def _is_rewrite_target(full, staging_root):
    base = os.path.basename(full)
    if base == _FINDER_BASENAME:
        return True
    if base.endswith(".pth"):
        return True
    if base == _DIRECT_URL_BASENAME:
        parent = os.path.basename(os.path.dirname(full))
        if parent == _DIRECT_URL_PARENT:
            return True
    return False


def _collect_rewrite_candidates(staging_root):
    finder_files = []
    pth_files = []
    direct_url_files = []
    pyvenv_files = []
    for dirpath, dirnames, filenames in os.walk(staging_root, topdown=False, followlinks=False):
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if name == "pyvenv.cfg":
                pyvenv_files.append(full)
                continue
            if name == _FINDER_BASENAME:
                # Skip .so? finder never .so.
                finder_files.append(full)
                continue
            if name.endswith(".pth"):
                pth_files.append(full)
                continue
            if name == _DIRECT_URL_BASENAME:
                parent = os.path.basename(dirpath)
                if parent == _DIRECT_URL_PARENT:
                    direct_url_files.append(full)
                    continue
    return finder_files, pth_files, direct_url_files, pyvenv_files


def _secure_overwrite(path, data):
    try:
        orig_st = os.lstat(path)
        mode = stat.S_IMODE(orig_st.st_mode)
    except FileNotFoundError:
        mode = 0o644
    tmp = path + ".tmp." + os.urandom(4).hex()
    flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
    fd = os.open(tmp, flags, mode)
    try:
        view = bytes(data)
        off = 0
        while off < len(view):
            n = os.write(fd, view[off:])
            if n == 0:
                raise OSError("short write")
            off += n
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
    parent = os.path.dirname(path)
    dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _rewrite_pyvenv(path, mount_prefix):
    with open(path, "rb") as f:
        data = f.read()
    new_home = (mount_prefix + "/interpreter/bin").encode()
    lines = data.split(b"\n")
    out_lines = []
    changed = False
    for line in lines:
        s = line.strip()
        if s.startswith(b"home"):
            parts = line.split(b"=", 1)
            if len(parts) == 2:
                out_lines.append(b"home = " + new_home)
                changed = True
                continue
        out_lines.append(line)
    new_data = b"\n".join(out_lines)
    if changed:
        _secure_overwrite(path, new_data)
    return changed


def _rewrite_prefixes_in_file(path, finder_prefixes, mount_source):
    with open(path, "rb") as f:
        data = f.read()
    # Never rewrite .so bytes.
    if path.endswith(".so"):
        return False
    new_data = data
    for pref in finder_prefixes:
        b = pref.encode() if isinstance(pref, str) else bytes(pref)
        if b in new_data:
            new_data = new_data.replace(b, mount_source.encode())
    if new_data != data:
        _secure_overwrite(path, new_data)
        return True
    return False


def _fsync_file_path(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_tree(root):
    # Bottom-up: files first, then dirs.
    for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
        for n in filenames:
            fp = os.path.join(dirpath, n)
            try:
                st = os.lstat(fp)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            fd = os.open(fp, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        # fsync dir itself
        dfd = os.open(dirpath, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _build_manifest(staging_root, bases):
    entries = []
    sroot = os.path.normpath(staging_root)
    for base in bases:
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            for name in list(dirnames) + list(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, sroot)
                try:
                    st = os.lstat(full)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    try:
                        target = os.readlink(full)
                    except OSError:
                        target = ""
                    entries.append((rel, "symlink", "-", target))
                elif stat.S_ISDIR(st.st_mode):
                    entries.append((rel, "dir", "-", "-"))
                elif stat.S_ISREG(st.st_mode):
                    h = _sha256_file(full)
                    entries.append((rel, "file", h, "-"))
                else:
                    raise RuntimeError("special manifest")
    entries.sort(key=lambda e: e[0])
    lines = []
    for rel, typ, h, tgt in entries:
        lines.append(f"{rel} {typ} {h} {tgt}")
    text = "\n".join(lines) + ("\n" if lines else "")
    digest = hashlib.sha256(text.encode()).hexdigest()
    return text, digest


def _find_node():
    cands = []
    w = shutil.which("node")
    if w:
        cands.append(w)
    for p in ("/usr/bin/node", "/opt/node24/bin/node", "/opt/node/bin/node"):
        if p not in cands and os.path.exists(p):
            cands.append(p)
    for p in cands:
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            return p
    return None


def _verify_web_dist_with_node(source_dir, dist_dir, runner=None):
    # Returns True if verified, False if omitted/unverified.
    # Never raises for mismatch; returns False.
    # Uses node directly with argv list, no shell. Runner is ignored
    # for this step so mock transports cannot fake verification.
    try:
        receipt_path = os.path.join(dist_dir, "hermes-build.json")
        with open(receipt_path, "rb") as f:
            receipt = json.loads(f.read().decode("utf-8"))
    except Exception:
        return False
    try:
        if receipt.get("schema") != 1:
            return False
        if receipt.get("product") != "web":
            return False
        inputs = receipt.get("inputs") or {}
        expected_source = inputs.get("sourceHash")
        expected_output = receipt.get("outputHash")
        if not isinstance(expected_source, str) or not isinstance(expected_output, str):
            return False
    except Exception:
        return False
    freshness = os.path.join(source_dir, "scripts", "build", "freshness.mjs")
    try:
        st = os.lstat(freshness)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    node_bin = _find_node()
    if node_bin is None:
        return False
    # Build inline verification program. Uses node only, argv list, no shell.
    # It imports sourceHash from the extracted freshness.mjs and recomputes
    # outputHash with the same treeHash logic.
    prog = (
        "import {createHash} from 'node:crypto';\n"
        "import {existsSync, readFileSync, readdirSync, statSync} from 'node:fs';\n"
        "import {join} from 'node:path';\n"
        "const source = process.argv[1];\n"
        "const out = process.argv[2];\n"
        "const expSource = process.argv[3];\n"
        "const expOutput = process.argv[4];\n"
        "const freshUrl = 'file://' + join(source, 'scripts/build/freshness.mjs');\n"
        "let mod;\n"
        "try { mod = await import(freshUrl); } catch(e) { console.error('fresh import fail:'+e); process.exit(2); }\n"
        "let gotSource;\n"
        "try { gotSource = mod.sourceHash(source, 'web'); } catch(e) { console.error('sourceHash fail:'+e); process.exit(2); }\n"
        "if (gotSource !== expSource) { console.error('sourceHash mismatch'); process.exit(1); }\n"
        "const receiptName='hermes-build.json';\n"
        "const generated=new Set(['node_modules','dist','dist-webapp','build','release','.cache','.git','coverage','test-results','playwright-report']);\n"
        "const osMetadata=(name)=>{const b=name.split('/').pop();return b==='.DS_Store'||b==='.localized'||b==='Thumbs.db'||b==='Desktop.ini'||b.startsWith('._');};\n"
        "function skipOut(name){return name===receiptName||name==='.hermes-product';}\n"
        "function contents(name){return !name.split('/').includes('node_modules') && !name.startsWith('native/');}\n"
        "function walkTree(root,inputs,skip,onEntry){function visit(name){if(osMetadata(name)||skip(name))return;const file=join(root,name);if(!existsSync(file))return onEntry(name,'missing');if(!statSync(file).isDirectory())return onEntry(name,'file');onEntry(name,'directory');for(const child of readdirSync(file).sort())visit(name+'/'+child);}for(const input of inputs)visit(input);}\n"
        "function treeHash(root,inputs,skip,cont){const h=createHash('sha256');walkTree(root,inputs,skip,(name,kind)=>{h.update(name.replaceAll('\\\\', '/')).update('\\0');if(kind==='file')h.update(cont(name)?readFileSync(join(root,name)):'file').update('\\0');else h.update(`${kind}\\0`);});return h.digest('hex');}\n"
        "let gotOutput;\n"
        "try{gotOutput=treeHash(out,readdirSync(out).sort(),skipOut,contents);}catch(e){console.error('outputHash fail:'+e);process.exit(2);}\n"
        "if(gotOutput!==expOutput){console.error('outputHash mismatch');process.exit(1);}\n"
        "process.exit(0);\n"
    )
    argv = [node_bin, "--input-type=module", "-e", prog, source_dir, dist_dir, expected_source, expected_output]
    # Note: node parses argv as [node, script, ...args]? With -e, process.argv is [node, ...args after prog?]
    # Actually with `node -e prog arg1 arg2`, process.argv = [node, arg1, arg2]? No, process.argv[0]=node, argv[1]=arg1...
    # Our prog uses process.argv[1] as source, so need to account: process.argv[0] is node path.
    # With -e, args after prog start at argv[1]. Good.
    env = {"PATH": "/usr/bin:/bin"}
    try:
        cp = subprocess.run(argv, shell=False, env=env, capture_output=True, check=False)
        rc = cp.returncode if hasattr(cp, "returncode") else 1
    except Exception:
        return False
    return rc == 0


def export_prep_closure(stage_root, *, kind, source_repo, source_sha,
                        venv_src, interpreter_src, deps_src=None,
                        finder_prefixes, mount_prefix, web_dist=None, runner=None):
    # Kind and deps validation first (no filesystem effects).
    if kind not in ("known-good", "candidate"):
        return _refused(kind if isinstance(kind, str) else "unknown")
    if kind == "candidate" and deps_src is not None:
        return _refused(kind)
    if kind == "known-good" and deps_src is None:
        return _refused(kind)
    if mount_prefix not in (_KNOWN_GOOD_MOUNT, _CANDIDATE_MOUNT):
        return _refused(kind)
    if not isinstance(finder_prefixes, (list, tuple)) or len(finder_prefixes) == 0:
        return _refused(kind)
    for p in finder_prefixes:
        if not isinstance(p, str) or not os.path.isabs(p):
            return _refused(kind)
    if not isinstance(source_sha, str) or source_sha == "":
        return _refused(kind)
    for v in (source_repo, venv_src, interpreter_src):
        if not isinstance(v, str) or not os.path.isabs(v):
            return _refused(kind)
    if deps_src is not None and (not isinstance(deps_src, str) or not os.path.isabs(deps_src)):
        return _refused(kind)
    if web_dist is not None and (not isinstance(web_dist, str) or not os.path.isabs(web_dist)):
        return _refused(kind)

    extra_forbidden = [source_repo, venv_src, interpreter_src, deps_src, web_dist]
    stage_norm, stage_err = _validate_stage_root(stage_root, extra_forbidden)
    if stage_err is not None:
        return _refused(kind)

    # All further paths stay under stage_norm.
    staging_parent = os.path.join(stage_norm, "staging")
    try:
        os.makedirs(staging_parent, exist_ok=True)
    except OSError:
        return _refused(kind)

    # Generate nonce staging dir.
    try:
        nonce = _generate_nonce()
    except Exception:
        return _refused(kind)
    staging_root = os.path.join(staging_parent, nonce)
    if os.path.lexists(staging_root):
        return _refused(kind)
    try:
        os.makedirs(staging_root, exist_ok=False)
    except OSError:
        return _refused(kind)

    def _cleanup_on_refuse(temp_image=None):
        try:
            if temp_image is not None and os.path.lexists(temp_image):
                try:
                    os.unlink(temp_image)
                except OSError:
                    pass
        except Exception:
            pass
        # Remove staging_root to avoid leaving partial tree.
        try:
            if os.path.lexists(staging_root):
                shutil.rmtree(staging_root, ignore_errors=True)
        except Exception:
            pass

    # Temp tars under staging_root (under stage only).
    tar1 = os.path.join(staging_root, "repo-1.tar")
    tar2 = os.path.join(staging_root, "repo-2.tar")
    if os.path.lexists(tar1) or os.path.lexists(tar2):
        _cleanup_on_refuse()
        return _refused(kind)

    git_env = {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    clean_env = {"PATH": "/usr/bin:/bin"}

    # Two hermetic archives.
    try:
        r1 = _run_cmd(_git_archive_argv(source_repo, source_sha, tar1), git_env, runner)
        r2 = _run_cmd(_git_archive_argv(source_repo, source_sha, tar2), git_env, runner)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind)
    rc1 = getattr(r1, "returncode", 1)
    rc2 = getattr(r2, "returncode", 1)
    if rc1 != 0 or rc2 != 0:
        _cleanup_on_refuse()
        return _refused(kind)
    try:
        h1 = _sha256_file(tar1)
        h2 = _sha256_file(tar2)
    except OSError:
        _cleanup_on_refuse()
        return _refused(kind)
    if h1 != h2:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=h1)
    archive_sha256 = h1

    source_dir = os.path.join(staging_root, "source")
    try:
        os.makedirs(source_dir, exist_ok=False)
    except OSError:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    try:
        rt = _run_cmd(_tar_extract_argv(source_dir, tar1), clean_env, runner)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)
    if getattr(rt, "returncode", 1) != 0:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # Remove tars so they never enter the image.
    for t in (tar1, tar2):
        try:
            os.unlink(t)
        except FileNotFoundError:
            pass
        except OSError:
            _cleanup_on_refuse()
            return _refused(kind, archive_sha256=archive_sha256)

    # Web dist verification before copy.
    web_status = "omitted-unverified"
    web_verified = False
    if web_dist is not None:
        # web_dist must exist and be a dir; otherwise omit.
        try:
            stw = os.lstat(web_dist)
            is_dir = stat.S_ISDIR(stw.st_mode) and not stat.S_ISLNK(stw.st_mode)
        except OSError:
            is_dir = False
        if is_dir:
            ok = _verify_web_dist_with_node(source_dir, web_dist, runner)
            if ok:
                web_verified = True
                web_status = "included-verified"
            else:
                # Fail closed: omit, do not copy.
                web_status = "omitted-unverified"
                web_verified = False
        else:
            web_status = "omitted-unverified"

    venv_dst = os.path.join(staging_root, "venv")
    interp_dst = os.path.join(staging_root, "interpreter")
    deps_dst = os.path.join(staging_root, "deps") if deps_src is not None else None

    # Rsync copies.
    try:
        for src, dst in [(venv_src, venv_dst), (interpreter_src, interp_dst)] + (
            [(deps_src, deps_dst)] if deps_src is not None else []
        ):
            rr = _run_cmd(_rsync_argv(src, dst), clean_env, runner)
            if getattr(rr, "returncode", 1) != 0:
                _cleanup_on_refuse()
                return _refused(kind, archive_sha256=archive_sha256)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # Web dist copy on match only.
    if web_verified:
        web_dest = os.path.join(source_dir, "hermes_cli", "web_dist")
        try:
            os.makedirs(os.path.dirname(web_dest), exist_ok=True)
            rw = _run_cmd(_rsync_argv(web_dist, web_dest), clean_env, runner)
            if getattr(rw, "returncode", 1) != 0:
                _cleanup_on_refuse()
                return _refused(kind, archive_sha256=archive_sha256)
            # Ensure .env never copied from dist (rsync already excludes).
            # Extra guard: remove any .env that slipped via other names? No, keep rsync policy.
            for dp, dn, fn in os.walk(web_dest, followlinks=False):
                if ".env" in fn:
                    cand = os.path.join(dp, ".env")
                    try:
                        os.unlink(cand)
                    except OSError:
                        pass
        except Exception:
            _cleanup_on_refuse()
            return _refused(kind, archive_sha256=archive_sha256)

    # Prune user sessions (preserve library sessions).
    try:
        _prune_user_sessions(staging_root)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # Deny checks.
    image_roots = [source_dir, venv_dst, interp_dst] + ([deps_dst] if deps_dst else [])
    try:
        for r in image_roots:
            _deny_tree(r)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # Symlink policy.
    venv_bins = set()
    for base in ([venv_dst] + ([deps_dst] if deps_dst else [])):
        b = os.path.join(base, "bin")
        try:
            stb = os.lstat(b)
            if stat.S_ISDIR(stb.st_mode) and not stat.S_ISLNK(stb.st_mode):
                venv_bins.add(b)
        except FileNotFoundError:
            continue
        except OSError:
            _cleanup_on_refuse()
            return _refused(kind, archive_sha256=archive_sha256)
    try:
        _handle_symlinks(staging_root, venv_bins)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)
    try:
        _replace_python_links(venv_bins)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # Rewrites, mount path only.
    mount_source = mount_prefix + "/source"
    mount_interp_bin = mount_prefix + "/interpreter/bin"
    _ = mount_interp_bin
    try:
        finder_files, pth_files, direct_url_files, pyvenv_files = _collect_rewrite_candidates(staging_root)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # Rewrite finder/direct_url/pth that reference prefixes.
    try:
        for full in finder_files + direct_url_files:
            # Skip .so (never matches, but guard).
            if full.endswith(".so"):
                continue
            _rewrite_prefixes_in_file(full, finder_prefixes, mount_source)
        for full in pth_files:
            if full.endswith(".so"):
                continue
            try:
                with open(full, "rb") as f:
                    data = f.read()
            except OSError:
                _cleanup_on_refuse()
                return _refused(kind, archive_sha256=archive_sha256)
            needs = False
            for pref in finder_prefixes:
                if pref.encode() in data:
                    needs = True
                    break
            if needs:
                _rewrite_prefixes_in_file(full, finder_prefixes, mount_source)
        for full in pyvenv_files:
            _rewrite_pyvenv(full, mount_prefix)
    except OSError:
        # Secure write fsync failure -> durable unknown.
        return _durable_unknown(kind, archive_sha256=archive_sha256, error="rewrite fsync")
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # After rewrite, refuse if finder prefixes or stage bytes remain.
    try:
        check_files = finder_files + direct_url_files + pyvenv_files
        # Include pth files that were rewritten (those containing prefix originally).
        # To be safe, include all pth files.
        check_files = check_files + pth_files
        stage_b = stage_norm.encode()
        for full in check_files:
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if full.endswith(".so"):
                continue
            with open(full, "rb") as f:
                data = f.read()
            for pref in finder_prefixes:
                if pref.encode() in data:
                    _cleanup_on_refuse()
                    return _refused(kind, archive_sha256=archive_sha256)
            if stage_b in data:
                _cleanup_on_refuse()
                return _refused(kind, archive_sha256=archive_sha256)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    # Residuals: regular files not in rewrite targets containing /home/ubuntu.
    residual = []
    try:
        rewrite_set = set(finder_files + pth_files + direct_url_files + pyvenv_files)
        for dirpath, dirnames, filenames in os.walk(staging_root, followlinks=False):
            for name in filenames:
                full = os.path.join(dirpath, name)
                if full in rewrite_set:
                    continue
                try:
                    st = os.lstat(full)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                # Do not rewrite .so, but do record.
                # Full scan for safety (files are small in prep).
                try:
                    with open(full, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                if b"/home/ubuntu" in data:
                    rel = os.path.relpath(full, staging_root)
                    residual.append(rel)
    except Exception:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)
    residual.sort()
    gate = "residual-embedded" if residual else "clean"

    # Fsync bottom-up.
    try:
        _fsync_tree(staging_root)
    except OSError as e:
        return _durable_unknown(kind, archive_sha256=archive_sha256, error=e)

    # Image temp: direct child of stage, not inside staged tree.
    image_tmp = os.path.join(stage_norm, f".prep-{nonce}.tmp.squashfs")
    if os.path.lexists(image_tmp):
        _cleanup_on_refuse(temp_image=image_tmp)
        return _refused(kind, archive_sha256=archive_sha256)
    # Guard: must be direct child and not under /var/lib.
    if os.path.dirname(os.path.normpath(image_tmp)) != stage_norm:
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)
    if _is_under(os.path.normpath(image_tmp), "/var/lib"):
        _cleanup_on_refuse()
        return _refused(kind, archive_sha256=archive_sha256)

    try:
        rm = _run_cmd(_mksquashfs_argv(staging_root, image_tmp), clean_env, runner)
    except Exception:
        _cleanup_on_refuse(temp_image=image_tmp)
        return _refused(kind, archive_sha256=archive_sha256)
    if getattr(rm, "returncode", 1) != 0:
        _cleanup_on_refuse(temp_image=image_tmp)
        return _refused(kind, archive_sha256=archive_sha256)

    # Fsync image, rename to final, fsync stage.
    final_image = os.path.join(stage_norm, f"{kind}.squashfs")
    try:
        _fsync_file_path(image_tmp)
    except OSError as e:
        try:
            if os.path.lexists(image_tmp):
                os.unlink(image_tmp)
        except OSError:
            pass
        return _durable_unknown(kind, archive_sha256=archive_sha256, error=e)
    try:
        # If final already exists, replace atomically via rename (overwrite).
        # Ensure no leftover verify confusion: allow overwrite.
        os.rename(image_tmp, final_image)
    except OSError as e:
        try:
            if os.path.lexists(image_tmp):
                os.unlink(image_tmp)
        except OSError:
            pass
        return _durable_unknown(kind, archive_sha256=archive_sha256, error=e)
    try:
        dfd = os.open(stage_norm, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError as e:
        return _durable_unknown(kind, archive_sha256=archive_sha256, error=e)

    # Manifest + image hashes.
    try:
        manifest_text, manifest_sha = _build_manifest(staging_root, image_roots)
        image_sha = _sha256_file(final_image)
        image_bytes = os.lstat(final_image).st_size
    except OSError as e:
        return _durable_unknown(kind, archive_sha256=archive_sha256, error=e)

    prep_path = os.path.join(stage_norm, f"{kind}.prep.json")
    payload = {
        "kind": kind,
        "source_sha": source_sha,
        "archive_sha256": archive_sha256,
        "manifest": manifest_text,
        "manifest_sha256": manifest_sha,
        "image_sha256": image_sha,
        "image_bytes": image_bytes,
        "image_path": final_image,
        "signed": False,
        "live_published": False,
        "kernel_immutable": False,
        "mount_executed": False,
        "activation": "UNEXECUTED",
        "web_dist": web_status,
        "design_absolute_gate": gate,
        "residual_embedded_paths": residual,
    }
    try:
        tmpj = prep_path + ".tmp." + os.urandom(4).hex()
        flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY
        fd = os.open(tmpj, flags, 0o644)
        try:
            data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
            off = 0
            while off < len(data):
                n = os.write(fd, data[off:])
                if n == 0:
                    raise OSError("short write")
                off += n
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(tmpj, 0o644)
        except OSError:
            pass
        os.rename(tmpj, prep_path)
        try:
            os.chmod(prep_path, 0o644)
        except OSError:
            pass
        dfd2 = os.open(stage_norm, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
        try:
            os.fsync(dfd2)
        finally:
            os.close(dfd2)
    except OSError as e:
        return _durable_unknown(kind, archive_sha256=archive_sha256, error=e)

    # Verify: unsquashfs and recompute.
    verify_dir = os.path.join(stage_norm, f"verify-{kind}")
    try:
        if os.path.lexists(verify_dir):
            if os.path.islink(verify_dir) or not os.path.isdir(verify_dir):
                try:
                    os.unlink(verify_dir)
                except OSError:
                    pass
            else:
                shutil.rmtree(verify_dir, ignore_errors=True)
        ru = _run_cmd(_unsquashfs_argv(final_image, verify_dir), clean_env, runner)
    except Exception:
        # Leave verify dir as is; delete success claim.
        try:
            if os.path.lexists(final_image):
                os.unlink(final_image)
        except OSError:
            pass
        try:
            if os.path.lexists(prep_path):
                os.unlink(prep_path)
        except OSError:
            pass
        return _refused(kind, archive_sha256=archive_sha256)
    if getattr(ru, "returncode", 1) != 0:
        try:
            if os.path.lexists(final_image):
                os.unlink(final_image)
        except OSError:
            pass
        try:
            if os.path.lexists(prep_path):
                os.unlink(prep_path)
        except OSError:
            pass
        return _refused(kind, archive_sha256=archive_sha256)

    try:
        v_source = os.path.join(verify_dir, "source")
        v_venv = os.path.join(verify_dir, "venv")
        v_interp = os.path.join(verify_dir, "interpreter")
        v_bases = [v_source, v_venv, v_interp]
        if deps_dst is not None:
            v_deps = os.path.join(verify_dir, "deps")
            v_bases.append(v_deps)
        v_text, v_sha = _build_manifest(verify_dir, v_bases)
    except Exception:
        try:
            if os.path.lexists(final_image):
                os.unlink(final_image)
        except OSError:
            pass
        try:
            if os.path.lexists(prep_path):
                os.unlink(prep_path)
        except OSError:
            pass
        return _refused(kind, archive_sha256=archive_sha256)
    if v_text != manifest_text or v_sha != manifest_sha:
        try:
            if os.path.lexists(final_image):
                os.unlink(final_image)
        except OSError:
            pass
        try:
            if os.path.lexists(prep_path):
                os.unlink(prep_path)
        except OSError:
            pass
        return _refused(kind, archive_sha256=archive_sha256)

    return {
        "status": "prep-staged",
        "success": True,
        "kind": kind,
        "image_path": final_image,
        "image_sha256": image_sha,
        "image_bytes": image_bytes,
        "manifest_sha256": manifest_sha,
        "manifest": manifest_text,
        "archive_sha256": archive_sha256,
        "digest_file": prep_path,
        "signed": False,
        "live_published": False,
        "kernel_immutable": False,
        "mount_executed": False,
        "activation": "UNEXECUTED",
        "web_dist": web_status,
        "design_absolute_gate": gate,
        "residual_embedded_paths": residual,
        "rollback_clean": True,
        "source_sha": source_sha,
    }
