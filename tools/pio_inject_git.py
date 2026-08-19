"""PlatformIO extra script: embed the git commit SHA into the firmware.

Defines FW_GIT_SHA="<short-sha>[+]" (+ = dirty worktree at build time) and
FW_GIT_TAG for tagged builds, so a flashed binary can be traced to the exact
source commit it was compiled from.
"""
import subprocess
Import("env")


def _git(*args):
    try:
        out = subprocess.check_output(
            ["git"] + list(args), stderr=subprocess.DEVNULL, cwd=os.path.abspath("."))
        return out.decode().strip()
    except Exception:
        return ""


import os  # noqa: E402  (kept near Import for readability)

sha = _git("rev-parse", "--short", "HEAD") or "unknown"
tag = _git("describe", "--tags", "--exact-match")
dirty = "+" if _git("status", "--porcelain") else ""
os.makedirs(".tmp", exist_ok=True)

env.Append(CPPDEFINES=[
    "FW_GIT_SHA=\\\"%s%s\\\"" % (sha, dirty),
    "FW_GIT_TAG=\\\"%s\\\"" % (tag or "-"),
])
print("git build id: %s%s%s" % (sha, dirty, " tag=" + tag if tag else ""))
