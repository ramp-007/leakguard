"""leakguard install-audit-tools - fetch TruffleHog, osv-scanner and Betterleaks (pinned versions, SHA-256 verified) into ~/.config/leakguard/bin."""
from __future__ import annotations
import hashlib
import platform
import tarfile
import tempfile
import zipfile
import urllib.request
from pathlib import Path

TRUFFLEHOG_VERSION = "3.99.7"
OSV_VERSION = "2.7.0"
BETTERLEAKS_VERSION = "1.9.0"


def _get(url: str) -> bytes:
    return urllib.request.urlopen(url, timeout=300).read()


def _platform() -> tuple[str, str]:
    osname = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(platform.system(), "")
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "amd64" if m in ("amd64", "x86_64") else ""
    if not osname or not arch:
        raise SystemExit(f"leakguard: no prebuilt build known for {platform.system()} {platform.machine()}; install the tool yourself")
    return osname, arch


def _verify(blob: bytes, sums: str, asset: str) -> None:
    want = next((l.split()[0] for l in sums.splitlines() if l.split() and l.split()[-1].lstrip("*") == asset), None)
    got = hashlib.sha256(blob).hexdigest()
    if not want or want != got:
        raise SystemExit(f"leakguard: checksum mismatch for {asset} (expected {want}, got {got}); not installed")


def install_trufflehog(dest: Path) -> str:
    osname, arch = _platform()
    base = f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_VERSION}/"
    asset = f"trufflehog_{TRUFFLEHOG_VERSION}_{osname}_{arch}.tar.gz"
    blob = _get(base + asset)
    _verify(blob, _get(base + f"trufflehog_{TRUFFLEHOG_VERSION}_checksums.txt").decode(), asset)
    exe = "trufflehog.exe" if osname == "windows" else "trufflehog"
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / asset
        tgz.write_bytes(blob)
        with tarfile.open(tgz) as t:
            t.extract(exe, dest)
    (dest / exe).chmod(0o755)
    return str(dest / exe)


def install_osv(dest: Path) -> str:
    osname, arch = _platform()
    base = f"https://github.com/google/osv-scanner/releases/download/v{OSV_VERSION}/"
    asset = f"osv-scanner_{osname}_{arch}" + (".exe" if osname == "windows" else "")
    blob = _get(base + asset)
    _verify(blob, _get(base + "osv-scanner_SHA256SUMS").decode(), asset)
    out = dest / ("osv-scanner.exe" if osname == "windows" else "osv-scanner")
    out.write_bytes(blob)
    out.chmod(0o755)
    return str(out)


def install_betterleaks(dest: Path) -> str:
    osname, arch = _platform()
    base = f"https://github.com/betterleaks/betterleaks/releases/download/v{BETTERLEAKS_VERSION}/"
    asset = f"betterleaks_{BETTERLEAKS_VERSION}_{osname}_{'x64' if arch == 'amd64' else arch}." + ("zip" if osname == "windows" else "tar.gz")
    blob = _get(base + asset)
    _verify(blob, _get(base + "checksums.txt").decode(), asset)
    exe = "betterleaks.exe" if osname == "windows" else "betterleaks"
    with tempfile.TemporaryDirectory() as td:
        pkg = Path(td) / asset
        pkg.write_bytes(blob)
        if asset.endswith(".zip"):
            zipfile.ZipFile(pkg).extract(exe, dest)
        else:
            with tarfile.open(pkg) as t:
                t.extract(exe, dest)
    (dest / exe).chmod(0o755)
    return str(dest / exe)


def install_audit_tools(central: Path) -> int:
    dest = central / "bin"
    dest.mkdir(parents=True, exist_ok=True)
    for name, fn in (("trufflehog", install_trufflehog), ("osv-scanner", install_osv), ("betterleaks", install_betterleaks)):
        print(f"installing {name} into {dest} ...")
        print("installed:", fn(dest))
    return 0
