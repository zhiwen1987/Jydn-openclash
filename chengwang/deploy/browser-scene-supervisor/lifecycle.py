"""CI-only lifecycle leaves; no application I/O or process launch on import.

These functions preserve observations and failures. They do not select a scene,
authorize a product action, or declare that a browser scenario passed.
"""
import hashlib
import pathlib
import subprocess


def append_process_records(tasks, records, native):
    """Append in place so an error retains earlier process observations."""
    for role, pid, executable, limit in tasks:
        record = native.task_profile(pid, hashlib.sha256(native.stable_read(executable, limit)[0]).hexdigest(), executable_limit=limit)
        record.update(role=role, argv=pathlib.Path('/proc', str(pid), 'cmdline').read_bytes()[:-1].decode().split('\0'))
        records.append(record)


def terminate_children(children, forced=0):
    """Keep caller order and count every actual terminate/kill intervention."""
    for child in children:
        if child is not None and child.poll() is None:
            forced += 1; child.terminate()
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: forced += 1; child.kill(); child.wait(timeout=3)
    return forced


def wait_namespace(child, *, wait_seconds=225, terminate_seconds=5, kill_seconds=3):
    """Return only the observed wait timeout; exit status remains the caller's."""
    timed_out = False
    try: child.wait(timeout=wait_seconds)
    except subprocess.TimeoutExpired: timed_out = True
    finally:
        if child.poll() is None:
            child.terminate()
            try: child.wait(timeout=terminate_seconds)
            except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=kill_seconds)
    return timed_out
