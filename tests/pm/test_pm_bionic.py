"""Behavior contracts for pm's bionic target + DebPackage + stage_only.

The lock VALUES are bumped by review; these tests pin the relationships:
the linux-arm64-bionic rows exist and agree with their suppliers' shapes,
DebPackage extraction is hardened, and cross-target staging never touches
this host's installed facts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def lock():
    return json.loads((REPO_ROOT / "pm" / "lock.json").read_text(encoding="utf-8"))


def test_all_targets_includes_bionic():
    from pm.store import ALL_TARGETS

    assert "linux-arm64-bionic" in ALL_TARGETS
    assert ALL_TARGETS.count("linux-arm64-bionic") == 1


def _assert_pinned_bionic_row(lock, pkg, url_suffix_re):
    """The bionic rows are DELIBERATE explicit pins: the version axis follows
    main (the desktop artifacts), while the termux/TUR suppliers rotate or
    lag, so the bionic row pins whatever the supplier actually ships today.
    The stage path consumes the row's url+sha256 directly. The contract:
    the row exists, is https, matches the supplier's filename shape, and
    fetch_url AGREES with the pinned row for this target."""
    import re as _re

    row = lock["packages"][pkg]["artifacts"].get("linux-arm64-bionic")
    assert row, f"{pkg} has no linux-arm64-bionic artifact"
    assert row["url"].startswith("https://"), f"{pkg} bionic row not https"
    m = _re.search(url_suffix_re, row["url"])
    assert m, f"{pkg} bionic url shape: {row['url']}"
    assert _re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
    from pm.registry import get_package

    cls = get_package(pkg)
    # fetch_url must reproduce the pinned row exactly for this target
    # (the pinned version is recovered from the URL itself).
    assert cls.fetch_url(m.group("ver"), "linux-arm64-bionic") == row["url"]


def test_python_bionic_row_matches_supplier(lock, monkeypatch):
    """The Python bionic row pins whatever the Termux pool serves (it lags standalone)."""
    import re as _re

    from pm import termux_libs
    from pm.registry import get_package

    row = lock["packages"]["python"]["artifacts"].get("linux-arm64-bionic")
    assert row, "python has no linux-arm64-bionic artifact"
    assert row["url"].startswith("https://")
    m = _re.search(r"/p/python/python_(?P<ver>[0-9.]+(?:-[0-9]+)?)_aarch64\.deb$", row["url"])
    assert m, f"python bionic url shape: {row['url']}"
    assert _re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
    # Hermetic: the pool index is the supplier authority, not the network.
    pool_url = row["url"]
    monkeypatch.setattr(
        termux_libs, "index", lambda: {"python": termux_libs.PoolPackage("python", m.group("ver"), pool_url, row["sha256"])}
    )
    assert get_package("python").fetch_url("3.14.9+20261021", "linux-arm64-bionic") == pool_url
    assert get_package("python").fetch_url(m.group("ver"), "linux-arm64-bionic") == pool_url


def test_node_bionic_row_matches_supplier(lock):
    """The node bionic row is an explicit pin of the termux-main nodejs .deb;
    the row and Nodejs.fetch_url(bionic arm) must agree (no Debian -1 revision)."""
    _assert_pinned_bionic_row(lock, "node", r"nodejs_(?P<ver>[0-9.]+)_aarch64\.deb$")
def test_termux_docker_row_pins_digest(lock):
    row = lock["packages"]["termux-docker"]["artifacts"]["linux-arm64-bionic"]
    version = lock["packages"]["termux-docker"]["version"]
    assert version.startswith("sha256:")
    assert len(version) == 7 + 64
    assert row["url"] == f"docker://termux/termux-docker@{version}"


def test_python_bionic_pin_is_independent_of_desktop_build_version(lock, monkeypatch):
    from pm import termux_libs
    from pm.registry import get_package

    py = get_package("python")
    package = lock["packages"]["python"]
    row = package["artifacts"]["linux-arm64-bionic"]
    monkeypatch.setattr(
        termux_libs, "index", lambda: {"python": termux_libs.PoolPackage("python", "3.14.8", row["url"], row["sha256"])}
    )
    assert py.fetch_url(package["version"], "linux-arm64-bionic") == row["url"]
    assert py.deb_package == "python"


def test_retired_bionic_urls_are_not_requested(monkeypatch):
    """The pinner must not request the retired 404 pool filenames.

    Node dropped the Debian -1 revision (nodejs_26.12.1, not -1); python
    3.14.6-1 retired and the pool serves 3.14.8. Both retired names 404.
    """
    from pm import termux_libs
    from pm.package import InstallError
    from pm.registry import get_package

    node_url = get_package("node").fetch_url("26.12.1", "linux-arm64-bionic")
    assert node_url == "https://packages.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.12.1_aarch64.deb"
    assert node_url not in (
        "https://packages.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.12.1-1_aarch64.deb",
        "https://packages.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.7.0-1_aarch64.deb",
        "https://packages.termux.dev/apt/termux-main/pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb",
    )
    assert "-1_aarch64.deb" not in node_url

    live_python = "https://packages.termux.dev/apt/termux-main/pool/main/p/python/python_3.14.8_aarch64.deb"
    monkeypatch.setattr(
        termux_libs, "index", lambda: {"python": termux_libs.PoolPackage("python", "3.14.8", live_python, "5" * 64)}
    )
    python_url = get_package("python").fetch_url("3.14.9+20261021", "linux-arm64-bionic")
    assert python_url == live_python
    assert python_url != get_package("python")._RETIRED_BIONIC_URL
    assert "python_3.14.6-1_aarch64.deb" not in python_url

    # Failing closed: no python in the pool is an explicit error, never a 404 URL.
    monkeypatch.setattr(termux_libs, "index", dict)
    with pytest.raises(InstallError, match="no python archive"):
        get_package("python").fetch_url("3.14.9+20261021", "linux-arm64-bionic")


def test_uv_bionic_row_matches_supplier(lock):
    """The uv bionic row is an explicit pin of the termux-main pool .deb;
    the row and Uv.fetch_url(bionic arm) must agree."""
    _assert_pinned_bionic_row(lock, "uv", r"/u/uv/uv_(?P<ver>[0-9.]+)_aarch64\.deb$")
@pytest.mark.parametrize("name,main,on_path", [
    ("python", None, True), ("uv", "bin/uv", False), ("node", "bin/node", True),
])
def test_registered_bionic_stage_preserves_host_facts(tmp_path, monkeypatch, lock, name, main, on_path):
    import hashlib
    from pm import paths
    from pm.install import stage_only
    from pm.lock import Lockfile
    from pm.package import InstallError
    from pm.registry import get_package
    from pm.store import Store
    from tests.termux_fixtures import build_deb

    target = "linux-arm64-bionic"
    monkeypatch.setenv("HERMES_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(paths, "lockfile_path", lambda: tmp_path / "lock.json")
    facts = paths.facts_path()
    facts.parent.mkdir(parents=True, exist_ok=True)
    facts.write_bytes(b'{"sentinel": "host state must not change"}')
    before = facts.read_bytes()
    if main is None:
        # Archive filename is the independent supplier authority, not main_rel().
        version = lock["packages"]["python"]["artifacts"][target]["url"].rsplit("/", 1)[1].split("_")[1]
        main = "bin/python" + ".".join(version.split(".")[:2])
    relative = "data/data/com.termux/files/usr/" + main
    package = get_package(name)
    store = Store(paths.store_root())

    def archive(files):
        deb = tmp_path / "fixture.deb"
        build_deb(deb, {"Package": name, "Version": "1.0"}, files)
        digest = hashlib.sha256(deb.read_bytes()).hexdigest()
        lock = Lockfile(paths.lockfile_path())
        lock.set_pin(name, "1.0", {target: {"url": "https://example.test/fixture.deb", "sha256": digest}})
        lock.save()
        cached = store.entry(f"fetch-{digest}")
        cached.mkdir(parents=True)
        (cached / "fixture.deb").write_bytes(deb.read_bytes())

    def no_exec(*args, **kwargs):
        pytest.fail(f"cross-target staging executed foreign bytes: {args}")

    monkeypatch.setattr("pm.packages.subprocess.run", no_exec)
    archive({relative: b"bionic-payload"})
    entry = stage_only(name, target)
    assert (entry / relative).read_bytes() == b"bionic-payload"
    assert package.binary(entry, target) == entry / relative
    assert package.env(entry, target).get("PATH") == ([str((entry / relative).parent)] if on_path else None)
    assert stage_only(name, target) == entry
    archive({"unrelated": b"not the main executable"})
    with pytest.raises(InstallError, match="missing"):
        stage_only(name, target)
    assert (entry / relative).read_bytes() == b"bionic-payload"
    assert facts.read_bytes() == before


def test_deb_rejects_traversal_before_touching_outside(tmp_path):
    from pm.package import DebPackage, InstallError
    from tests.termux_fixtures import build_deb

    sentinel = tmp_path / "escape"
    sentinel.write_bytes(b"owned outside extraction")
    deb = tmp_path / "evil.deb"
    build_deb(deb, {"Package": "evil"}, {"../escape": b"overwrite"})
    with pytest.raises(InstallError, match="unsafe|escape|traversal"):
        DebPackage().unpack(deb, tmp_path / "staged", "linux-arm64-bionic")
    assert sentinel.read_bytes() == b"owned outside extraction"
