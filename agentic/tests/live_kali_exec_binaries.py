"""LIVE: every binary kali_exec allowlists must exist in the sandbox image.

The allowlist lives in the AGENT image (kali_exec_guard.py) and the binaries
live in the KALI image, so nothing hermetic can see both. They drifted on the
first real run: `dnsx`, `wafw00f`, `subzy` and `hashid` were allowlisted and had
never been installed, and `httpx` resolved to the PYTHON httpx CLI rather than
ProjectDiscovery's, so every flag the RedAmon catalogue documents for it failed.

An allowlist that names a missing tool is worse than a shorter one: it advertises
a capability that does not exist, and the caller gets a confusing "[ERROR] not
found" from the tool instead of a clean refusal naming what it can use.

Self-skips without a running kali-sandbox, per the repo's live-tier rule.
"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kali_exec_guard import ALLOWED_BINARIES  # noqa: E402

CONTAINER = "redamon-kali"


def _unavailable_reason() -> str:
    """Why this cannot run, or '' when it can.

    Distinguished on purpose. "no docker client" is the normal answer inside the
    gate containers (they have no docker CLI, and bind-mounting the host one
    fails on its shared libraries), while "not running" means someone ran the
    live tier against a stack that is down. Collapsing the two into one skip
    line makes a skipped run unreadable, and a skip that looks like a pass is
    the failure mode this repo's testing rules single out.
    """
    if not shutil.which("docker"):
        return "no docker client on PATH (expected inside the gate containers)"
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"docker client unusable: {exc}"
    if out.returncode != 0:
        return f"{CONTAINER} not found (stack down?)"
    if out.stdout.strip() != "true":
        return f"{CONTAINER} is not running"
    return ""


class AllowlistedBinariesExistTests(unittest.TestCase):
    def setUp(self):
        reason = _unavailable_reason()
        if reason:
            self.skipTest(reason)

    def test_every_allowlisted_binary_is_installed(self):
        names = sorted(ALLOWED_BINARIES)
        probe = "; ".join(f'command -v {n} >/dev/null || echo MISSING:{n}' for n in names)
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "bash", "-lc", probe],
            capture_output=True, text=True, timeout=120,
        )
        missing = [
            line.split(":", 1)[1]
            for line in result.stdout.splitlines()
            if line.startswith("MISSING:")
        ]
        self.assertEqual(
            missing, [],
            f"kali_exec allowlists {missing}, which the sandbox image does not install. "
            "Either install them or drop them from NETWORK_BINARIES / OFFLINE_BINARIES.",
        )


if __name__ == "__main__":
    unittest.main()
