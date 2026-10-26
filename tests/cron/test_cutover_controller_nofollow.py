"""No-follow controller identity regression (ProductionHost, real disk).

Red first: on the vulnerable base these tests FAIL because the gate follows
the final symlink (ProductionHost.read_bytes is Path.read_bytes) and only
lstats the facade, swallowing NotImplementedError/OSError.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.maintenance.cutover_manifest import (
    EXPECTED_SIBLINGS,
    ManifestError,
    external_controller_provenance,
)
from scripts.maintenance.cutover_preflight import (
    PreflightError,
    _refuse_controller_inside_candidate,
)
from scripts.maintenance.cutover_types import ProductionHost


class NoEffectHost(ProductionHost):
    """Real disk reads, but any effect explodes (no run/write/remove/http)."""

    def run(self, argv, timeout=60, cwd=None, env=None):  # type: ignore[override]
        raise AssertionError(f"run must not be called: {argv}")

    def write_bytes(self, path, data):  # type: ignore[override]
        raise AssertionError(f"write_bytes must not be called: {path}")

    def remove(self, path):  # type: ignore[override]
        raise AssertionError(f"remove must not be called: {path}")

    def http_get(self, url, timeout=10):  # type: ignore[override]
        raise AssertionError(f"http_get must not be called: {url}")


def _write_regular(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _seed_external_dir(ctrl_dir: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for name in EXPECTED_SIBLINGS:
        if name == "cutover.py":
            data = b"from scripts.maintenance.cutover_orchestrate import orchestrate, resume\n"
        elif name == "cutover_orchestrate.py":
            data = b"def orchestrate(host, config): pass\ndef resume(host, config): pass\n"
        else:
            data = f"# {name} external stub\n".encode()
        _write_regular(ctrl_dir / name, data)
        payloads[name] = data
    return payloads


def _call_provenance(host, facade: Path, candidate_src: Path):
    """Call the production provenance gate with candidate context when supported."""
    try:
        return external_controller_provenance(host, facade, candidate_src)  # type: ignore[call-arg]
    except TypeError:
        return external_controller_provenance(host, facade)


def _call_refuse(facade: Path, candidate_src: Path) -> None:
    _refuse_controller_inside_candidate(facade, candidate_src)


def test_case_a_symlink_sibling_to_inside_candidate_refuses(tmp_path: Path) -> None:
    """Cutover_orchestrate symlink to a file inside candidate must not satisfy gate."""
    ext = tmp_path / "ext-controller"
    candidate = tmp_path / "candidate"
    _seed_external_dir(ext)
    cand_maint = candidate / "scripts" / "maintenance"
    cand_file = cand_maint / "cutover_orchestrate.py"
    _write_regular(cand_file, b"def orchestrate(host, config): return 'candidate'\n")
    # Replace external sibling with a symlink to the candidate file.
    (ext / "cutover_orchestrate.py").unlink()
    (ext / "cutover_orchestrate.py").symlink_to(cand_file)
    facade = ext / "cutover.py"
    host = NoEffectHost()
    refused = False
    try:
        _call_refuse(facade, candidate)
    except PreflightError:
        refused = True
    if not refused:
        try:
            prov = _call_provenance(host, facade, candidate)
        except (ManifestError, PreflightError):
            refused = True
        else:
            cand_digest = hashlib.sha256(cand_file.read_bytes()).hexdigest()
            assert prov.get("sibling_sha256", {}).get("cutover_orchestrate.py") != cand_digest, (
                "gate returned candidate bytes as external success"
            )
            assert prov.get("signed") is not True
            raise AssertionError("symlink sibling to candidate was accepted")
    assert refused, "symlink sibling to inside candidate must refuse"


def test_case_b_symlink_to_outside_still_refuses(tmp_path: Path) -> None:
    """Every sibling symlink refuses even when its target is outside the candidate."""
    ext = tmp_path / "ext-controller"
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True, exist_ok=True)
    _seed_external_dir(ext)
    outside = tmp_path / "outside-target.py"
    _write_regular(outside, b"def orchestrate(host, config): pass\n")
    (ext / "cutover_orchestrate.py").unlink()
    (ext / "cutover_orchestrate.py").symlink_to(outside)
    facade = ext / "cutover.py"
    host = NoEffectHost()
    try:
        prov = _call_provenance(host, facade, candidate)
    except (ManifestError, PreflightError):
        return
    raise AssertionError(f"symlink to outside was accepted: {prov.get('sibling_sha256', {}).get('cutover_orchestrate.py')}")


def test_case_c_same_name_hardlink_refuses(tmp_path: Path) -> None:
    """Same-name hardlink from external sibling to candidate file must refuse."""
    ext = tmp_path / "ext-controller"
    candidate = tmp_path / "candidate"
    _seed_external_dir(ext)
    cand_maint = candidate / "scripts" / "maintenance"
    cand_file = cand_maint / "cutover_orchestrate.py"
    _write_regular(cand_file, b"def orchestrate(host, config): return 'candidate-hardlink'\n")
    ext_file = ext / "cutover_orchestrate.py"
    ext_file.unlink()
    try:
        import os as _os

        _os.link(cand_file, ext_file)
    except OSError as exc:
        pytest.fail(f"filesystem does not allow hardlink; failing closed: {exc}")
    facade = ext / "cutover.py"
    host = NoEffectHost()
    try:
        _call_provenance(host, facade, candidate)
    except (ManifestError, PreflightError):
        return
    raise AssertionError("same-name hardlink was accepted")


# --- Case D: uncertain lstat fails closed via the real preflight entrypoint ---

def test_case_d_uncertain_lstat_refuses_before_mutation(tmp_path: Path) -> None:
    """Non-facade sibling with uncertain stat must refuse pre-mutation."""
    from scripts.maintenance.cutover_preflight import preflight
    from scripts.maintenance.cutover_types import CutoverConfig, FileStat, Host, RunResult

    class _Fake(Host):
        def __init__(self) -> None:
            self.files: dict[str, bytes] = {}
            self.stats: dict[str, object] = {}
            self.ran: list[str] = []
            self.wrote: list[str] = []

        def run(self, argv, timeout=60, cwd=None, env=None):  # type: ignore[override]
            self.ran.append(" ".join(argv))
            raise AssertionError("run must not be called pre-mutation")

        def read_bytes(self, path):  # type: ignore[override]
            key = str(path)
            if key in self.files:
                value = self.files[key]
                assert isinstance(value, bytes)
                return value
            raise FileNotFoundError(key)

        def write_bytes(self, path, data):  # type: ignore[override]
            self.wrote.append(str(path))
            raise AssertionError("write_bytes must not be called pre-mutation")

        def remove(self, path):  # type: ignore[override]
            raise AssertionError("remove must not be called")

        def proc_exe(self, pid):  # type: ignore[override]
            raise AssertionError("proc_exe must not be called")

        def proc_cmdline(self, pid):  # type: ignore[override]
            raise AssertionError("proc_cmdline must not be called")

        def proc_cwd(self, pid):  # type: ignore[override]
            raise AssertionError("proc_cwd must not be called")

        def proc_environ(self, pid):  # type: ignore[override]
            raise AssertionError("proc_environ must not be called")

        def proc_start_time(self, pid):  # type: ignore[override]
            raise AssertionError("proc_start_time must not be called")

        def stat_file(self, path):  # type: ignore[override]
            key = str(path)
            if key in self.stats:
                value = self.stats[key]
                if isinstance(value, Exception):
                    raise value
                assert isinstance(value, FileStat)
                return value
            raise FileNotFoundError(key)

        def http_get(self, url, timeout=10):  # type: ignore[override]
            raise AssertionError("http_get must not be called")

        # Bound read used after the fix; before the fix it is ignored.
        def read_bytes_nofollow(self, path):  # type: ignore[override]
            key = str(path)
            if key not in self.files:
                raise FileNotFoundError(key)
            data = self.files[key]
            assert isinstance(data, bytes)
            st = self.stats.get(key)
            if isinstance(st, Exception):
                raise st
            if not isinstance(st, FileStat):
                raise FileNotFoundError(key)
            dev = getattr(st, "dev", None)
            ino = getattr(st, "ino", None)
            if dev is None or ino is None:
                # Old FileStat without dev/ino: return bytes only shape.
                # Production after the fix requires dev/ino and will refuse;
                # this keeps the red run exercising the old byte gate.
                return bytes(data), 0, 0
            if not isinstance(dev, int) or not isinstance(ino, int):
                raise OSError(f"uncertain identity for {key}")
            return bytes(data), int(dev), int(ino)

    def _config() -> CutoverConfig:
        return CutoverConfig(
            candidate_sha="a" * 40,
            parent_sha="b" * 40,
            candidate_src=tmp_path / "candidate",
            live_tree=tmp_path / "live",
            generation_root=tmp_path / "generations",
            journal_path=tmp_path / "journal.jsonl",
            hermes_home=tmp_path / "home",
            gateway_unit="hermes-gateway.service",
            dashboard_unit="hermes-dashboard.service",
            gateway_dropin_dir=tmp_path / "gw.d",
            dashboard_dropin_dir=tmp_path / "dash.d",
            candidate_dropin_name="zzz-candidate.conf",
            dashboard_port=9119,
            controller_path=tmp_path / "ext-controller" / "cutover.py",
        )

    def _seed(host: _Fake, config: CutoverConfig) -> None:
        ctrl_dir = Path(config.controller_path).parent
        base_dev = 100
        for idx, name in enumerate(EXPECTED_SIBLINGS):
            if name == "cutover.py":
                data = b"from scripts.maintenance.cutover_orchestrate import orchestrate, resume\n"
            elif name == "cutover_orchestrate.py":
                data = b"def orchestrate(host, config): pass\ndef resume(host, config): pass\n"
            else:
                data = f"# {name} external stub\n".encode()
            host.files[str(ctrl_dir / name)] = data
            host.stats[str(ctrl_dir / name)] = FileStat(
                uid=0,
                gid=0,
                mode=0o644,
                is_symlink=False,
                is_file=True,
                dev=base_dev,
                ino=1000 + idx,
            )

    # Sub-case 1: NotImplementedError on a non-facade sibling.
    config = _config()
    host = _Fake()
    _seed(host, config)
    victim = str(Path(config.controller_path).parent / "cutover_stage.py")
    host.stats[victim] = NotImplementedError("no lstat")
    try:
        preflight(host, config)
    except (PreflightError, ManifestError):
        pass
    except AssertionError as exc:
        raise AssertionError(f"NotImplementedError sibling stat bypassed gate, reached mutation: {exc}") from exc
    else:
        raise AssertionError("NotImplementedError sibling stat was accepted")
    assert host.ran == []
    assert host.wrote == []

    # Sub-case 2: generic OSError (not FileNotFoundError) on a non-facade sibling.
    config2 = _config()
    host2 = _Fake()
    _seed(host2, config2)
    victim2 = str(Path(config2.controller_path).parent / "cutover_journal.py")
    host2.stats[victim2] = OSError("EIO")
    try:
        preflight(host2, config2)
    except (PreflightError, ManifestError):
        pass
    except AssertionError as exc:
        raise AssertionError(f"OSError sibling stat bypassed gate, reached mutation: {exc}") from exc
    else:
        raise AssertionError("OSError sibling stat was accepted")
    assert host2.ran == []
    assert host2.wrote == []

    # Sub-case 3: symlink FileStat on a non-facade sibling.
    config3 = _config()
    host3 = _Fake()
    _seed(host3, config3)
    victim3 = str(Path(config3.controller_path).parent / "cutover_receipt.py")
    host3.stats[victim3] = FileStat(
        uid=0, gid=0, mode=0o644, is_symlink=True, is_file=True, dev=100, ino=9999
    )
    try:
        preflight(host3, config3)
    except (PreflightError, ManifestError):
        pass
    except AssertionError as exc:
        raise AssertionError(f"symlink non-facade sibling bypassed gate, reached mutation: {exc}") from exc
    else:
        raise AssertionError("symlink non-facade sibling was accepted")
    assert host3.ran == []
    assert host3.wrote == []


def test_case_e_hardlink_with_uncertain_candidate_lstat_refuses(tmp_path: Path) -> None:
    """Hardlink alias plus uncertain candidate lstat must refuse (fail closed)."""
    ext = tmp_path / "ext-controller"
    candidate = tmp_path / "candidate"
    _seed_external_dir(ext)
    cand_maint = candidate / "scripts" / "maintenance"
    cand_file = cand_maint / "cutover_orchestrate.py"
    _write_regular(
        cand_file, b"def orchestrate(host, config): pass\ndef resume(host, config): pass\n"
    )
    ext_file = ext / "cutover_orchestrate.py"
    ext_file.unlink()
    try:
        import os as _os

        _os.link(cand_file, ext_file)
    except OSError as exc:
        pytest.fail(f"filesystem does not allow hardlink; failing closed: {exc}")
    facade = ext / "cutover.py"
    candidate_same = candidate / "scripts" / "maintenance" / "cutover_orchestrate.py"

    class _UncertainCandidateHost(NoEffectHost):
        def stat_file(self, path):  # type: ignore[override]
            if str(Path(path)) == str(candidate_same):
                raise OSError("EIO uncertain candidate alias")
            return super().stat_file(path)

    host = _UncertainCandidateHost()
    try:
        prov = _call_provenance(host, facade, candidate)
    except (ManifestError, PreflightError):
        return
    raise AssertionError(
        f"hardlink with uncertain candidate lstat was accepted: signed={prov.get('signed')} "
        f"stat_available={prov.get('stat_available')}"
    )


def test_case_f_bool_dev_ino_refuses(tmp_path: Path) -> None:
    """Bool device/inode must refuse (type(x) is int, no int() coercion)."""
    from scripts.maintenance.cutover_types import FileStat, Host

    class _BoolHost(Host):
        def __init__(self) -> None:
            self.files: dict[str, bytes] = {}
            self.stats: dict[str, object] = {}

        def run(self, argv, timeout=60, cwd=None, env=None):  # type: ignore[override]
            raise AssertionError("run must not be called")

        def read_bytes(self, path):  # type: ignore[override]
            raise AssertionError("read_bytes must not be called for identity")

        def write_bytes(self, path, data):  # type: ignore[override]
            raise AssertionError("write_bytes must not be called")

        def remove(self, path):  # type: ignore[override]
            raise AssertionError("remove must not be called")

        def proc_exe(self, pid):  # type: ignore[override]
            raise AssertionError("proc_exe must not be called")

        def proc_cmdline(self, pid):  # type: ignore[override]
            raise AssertionError("proc_cmdline must not be called")

        def proc_cwd(self, pid):  # type: ignore[override]
            raise AssertionError("proc_cwd must not be called")

        def proc_environ(self, pid):  # type: ignore[override]
            raise AssertionError("proc_environ must not be called")

        def proc_start_time(self, pid):  # type: ignore[override]
            raise AssertionError("proc_start_time must not be called")

        def stat_file(self, path):  # type: ignore[override]
            key = str(path)
            if key in self.stats:
                value = self.stats[key]
                if isinstance(value, Exception):
                    raise value
                assert isinstance(value, FileStat)
                return value
            raise FileNotFoundError(key)

        def http_get(self, url, timeout=10):  # type: ignore[override]
            raise AssertionError("http_get must not be called")

        def read_bytes_nofollow(self, path):  # type: ignore[override]
            key = str(path)
            if key not in self.files:
                raise FileNotFoundError(key)
            data = self.files[key]
            assert isinstance(data, bytes)
            return bytes(data), True, True  # type: ignore[return-value]

    ext = tmp_path / "ext-controller"
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True, exist_ok=True)
    host = _BoolHost()
    for name in EXPECTED_SIBLINGS:
        if name == "cutover.py":
            data = b"from scripts.maintenance.cutover_orchestrate import orchestrate, resume\n"
        elif name == "cutover_orchestrate.py":
            data = b"def orchestrate(host, config): pass\ndef resume(host, config): pass\n"
        else:
            data = f"# {name} external stub\n".encode()
        key = str(ext / name)
        host.files[key] = data
        host.stats[key] = FileStat(
            uid=0,
            gid=0,
            mode=0o644,
            is_symlink=False,
            is_file=True,
            dev=True,  # type: ignore[arg-type]
            ino=True,  # type: ignore[arg-type]
        )
    facade = ext / "cutover.py"
    try:
        prov = _call_provenance(host, facade, candidate)
    except (ManifestError, PreflightError):
        return
    # Old gate coerced True -> 1 and recorded dev 1, ino 1.
    recorded = prov.get("sibling_stat", {}).get("cutover.py", {})
    raise AssertionError(f"bool dev/ino was accepted: {recorded}")


def test_case_g_absent_candidate_same_name_allows_distinct(tmp_path: Path) -> None:
    """Absent candidate same-name (FileNotFoundError) still allows distinct reals."""
    ext = tmp_path / "ext-controller"
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True, exist_ok=True)
    payloads = _seed_external_dir(ext)
    facade = ext / "cutover.py"
    host = NoEffectHost()
    prov = _call_provenance(host, facade, candidate)
    assert prov.get("signed") is False
    assert prov.get("stat_available") is True
    assert set(prov.get("sibling_sha256", {})) == set(EXPECTED_SIBLINGS)
    for name, data in payloads.items():
        assert prov["sibling_sha256"][name] == hashlib.sha256(data).hexdigest()
    for name, stat in prov.get("sibling_stat", {}).items():
        assert type(stat["dev"]) is int
        assert type(stat["ino"]) is int
