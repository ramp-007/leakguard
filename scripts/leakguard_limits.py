# leakguard-managed: generated copy; refresh with `leakguard.py init --update` from the leakguard repo
"""Run a child process with a wall-clock timeout and a memory cap, so a runaway scan cannot freeze the machine.

Windows: the child is placed in a Job Object (per-process memory limit, killed when the job closes).
POSIX: RLIMIT_AS is set in the child before exec (not on macOS, which refuses to lower it).
In all cases the child is killed on timeout.
"""
from __future__ import annotations
import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

DEFAULT_TIMEOUT_SEC = 120
DEFAULT_MEMORY_BYTES = 4 * 1024**3

_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _make_job(memory_bytes: int) -> wintypes.HANDLE:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    info = _ExtendedLimits()
    info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_PROCESS_MEMORY | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    info.ProcessMemoryLimit = memory_bytes
    ok = k32.SetInformationJobObject(wintypes.HANDLE(job), _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info))
    if not ok:
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
    return job


def _assign(job: wintypes.HANDLE, proc: "subprocess.Popen[str]") -> None:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    handle = k32.OpenProcess(0x0100 | 0x0001, False, proc.pid)  # PROCESS_SET_QUOTA | PROCESS_TERMINATE
    if not handle or not k32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(handle)):
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    k32.CloseHandle(wintypes.HANDLE(handle))


def run_limited(
    cmd: list[str],
    cwd: Path,
    timeout: int = DEFAULT_TIMEOUT_SEC,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
) -> tuple[int, str, str, str]:
    """Return (returncode, stdout, stderr, reason). reason is "" on a normal exit, else why it was stopped."""
    env = dict(os.environ)
    env.setdefault("GOMEMLIMIT", f"{memory_bytes // 2}B")  # make the Go GC work harder before the hard cap bites
    kwargs: dict[str, object] = {}
    # macOS rejects lowering RLIMIT_AS ("current limit exceeds maximum limit"), which made every scan fail;
    # there GOMEMLIMIT and the timeout are the only bounds.
    if os.name != "nt" and sys.platform != "darwin":
        import resource

        # RLIMIT_AS counts virtual size, and gitleaks (go-re2 on wazero) reserves a 4 GiB range at start-up,
        # so capping at memory_bytes itself makes it abort. Leave headroom; GOMEMLIMIT and the timeout bound real use.
        address_space = max(memory_bytes * 4, 16 * 1024**3)

        def _cap() -> None:
            resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))

        kwargs["preexec_fn"] = _cap
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", **kwargs,  # type: ignore[arg-type]
    )
    if os.name == "nt":
        try:
            _assign(_make_job(memory_bytes), proc)
        except OSError as e:
            proc.kill()
            proc.communicate()
            return 1, "", "", f"could not apply the memory cap ({e}); refusing to run unbounded"
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 1, out, err, f"timed out after {timeout}s and was killed"
    reason = ""
    if proc.returncode not in (0, 1):  # gitleaks: 0 clean, 1 leaks (via --exit-code); anything else is a crash or the memory cap
        reason = f"exited abnormally (code {proc.returncode}); possibly the {memory_bytes // 1024**2} MiB memory cap"
    return proc.returncode, out, err, reason
