#!/usr/bin/env python3
"""Packing check: the five release files go through the SDK's own packer.

Stages manifest.json, icon.png, port-forwarder.exe, LICENSE and THIRD_PARTY_NOTICES.txt in a
temporary pkg/ -- exactly what release.yml uploads -- and runs

    gpkg.py pack --src pkg --out dist --min-app-version 1.2.1

from the public SDK (liliBestCoder/ghost-plugin-sdk). Then checks what came out: the .gpkg
and ghost-plugin.json and nothing else; the release descriptor's id/version (the manifest's),
minAppVersion (1.2.1, the first Ghost with upstream.connect), package name, size and SHA-256
(the file's); the archive holds exactly the five files, stored, byte for byte. And that the
SDK refuses 1.2.0 for this manifest -- so the floor above is the SDK's rule, not a number
this test made up.

Usage: test_pack.py --sdk <ghost-plugin-sdk checkout> --exe <port-forwarder.exe>
                    --src <repository root> [--require]

The SDK must be the commit CI and the release pack with: when the SDK directory is a git
checkout, its HEAD has to equal the SDK_REF pinned in .github/workflows/ci.yml (which
check_workflows.py keeps equal to release.yml's). A packer from another commit could pass here
and fail -- or pack differently -- in the release. Only a directory that is not a git checkout
(an extracted archive, say) skips this comparison, and says so.

Exit 77 (CTest: Skipped) when the SDK checkout is missing, unless --require (CI) -- then 1.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

SKIP = 77
MIN_APP = "1.2.1"
FILES = ["manifest.json", "icon.png", "port-forwarder.exe", "LICENSE", "THIRD_PARTY_NOTICES.txt"]

failures = []


def check(cond, label):
    if not cond:
        failures.append(label)
        print("FAIL: " + label, flush=True)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def pinned_sdk_ref(src):
    """The SDK_REF in .github/workflows/ci.yml, or None (with the reason printed)."""
    path = os.path.join(src, ".github", "workflows", "ci.yml")
    try:
        with open(path, "rb") as f:
            text = f.read().decode("utf-8")
    except OSError as e:
        print("cannot read %s: %s" % (path, e), flush=True)
        return None
    refs = re.findall(r"^\s+SDK_REF:\s*(\S+)\s*$", text, re.M)
    if len(refs) != 1 or not re.match(r"^[0-9a-f]{40}$", refs[0]):
        print("%s must set SDK_REF exactly once, to a 40-hex commit: %r" % (path, refs), flush=True)
        return None
    return refs[0]


def check_sdk_commit(sdk, src):
    """The SDK checkout is the pinned commit (a git checkout), or not a git checkout at all."""
    pinned = pinned_sdk_ref(src)
    check(pinned is not None, "ci.yml pins SDK_REF")
    if pinned is None:
        return
    if not os.path.exists(os.path.join(sdk, ".git")):
        print("the SDK at %s is not a git checkout (no .git) -- its commit cannot be compared with "
              "SDK_REF %s; packing with it as it is" % (sdk, pinned), flush=True)
        return
    try:
        r = subprocess.run(["git", "-C", sdk, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        check(False, "the SDK is a git checkout but `git rev-parse HEAD` could not run: %s" % e)
        return
    head = r.stdout.strip()
    check(r.returncode == 0 and head == pinned,
          "the SDK checkout at %s is at %s, but ci.yml pins SDK_REF %s -- check out that commit "
          "(git -C <sdk> checkout %s) or update SDK_REF in both workflows"
          % (sdk, head or ("<rev-parse failed: %s>" % r.stderr.strip()), pinned, pinned))


def run_pack(gpkg, src, out, min_app):
    return subprocess.run(
        [sys.executable, gpkg, "pack", "--src", src, "--out", out, "--min-app-version", min_app],
        capture_output=True, text=True, timeout=120)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", required=True)
    ap.add_argument("--exe", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--require", action="store_true")
    a = ap.parse_args()

    gpkg = os.path.join(a.sdk, "tools", "plugin", "gpkg.py")
    if not os.path.isfile(gpkg):
        print("the SDK's gpkg.py is not at %s (set GHOST_PLUGIN_SDK or -DPF_GHOST_SDK_DIR)" % gpkg, flush=True)
        return 1 if a.require else SKIP

    check_sdk_commit(a.sdk, a.src)

    with open(os.path.join(a.src, "manifest.json"), "rb") as f:
        manifest = json.loads(f.read().decode("utf-8"))
    pid, version = manifest["id"], manifest["version"]

    with tempfile.TemporaryDirectory(prefix="pf_pack_") as tmp:
        pkg = os.path.join(tmp, "pkg")
        dist = os.path.join(tmp, "dist")
        os.makedirs(pkg)
        sources = {}
        for name in FILES:
            src = a.exe if name == "port-forwarder.exe" else os.path.join(a.src, name)
            shutil.copyfile(src, os.path.join(pkg, name))
            sources[name] = src

        r = run_pack(gpkg, pkg, dist, MIN_APP)
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
        check(r.returncode == 0, "gpkg.py pack exits 0 (got %d)" % r.returncode)
        if r.returncode != 0:
            return 1

        gpkg_name = "%s-%s.gpkg" % (pid, version)
        check(sorted(os.listdir(dist)) == sorted(["ghost-plugin.json", gpkg_name]),
              "dist holds the release descriptor and the package, nothing else: %r" % sorted(os.listdir(dist)))
        pkg_path = os.path.join(dist, gpkg_name)
        desc_path = os.path.join(dist, "ghost-plugin.json")
        if not (os.path.isfile(pkg_path) and os.path.isfile(desc_path)):
            return 1

        with open(desc_path, "rb") as f:
            desc = json.loads(f.read().decode("utf-8"))
        check(desc.get("v") == 1, "descriptor v == 1")
        check(desc.get("id") == pid, "descriptor id == manifest id")
        check(desc.get("version") == version, "descriptor version == manifest version")
        check(desc.get("minAppVersion") == MIN_APP, "minAppVersion == %s (got %r)" % (MIN_APP, desc.get("minAppVersion")))
        p = desc.get("package") or {}
        check(p.get("name") == gpkg_name, "package.name == %s" % gpkg_name)
        check(p.get("size") == os.path.getsize(pkg_path), "package.size is the file's size")
        check(p.get("sha256") == sha256(pkg_path), "package.sha256 is the file's digest")

        with zipfile.ZipFile(pkg_path) as z:
            infos = z.infolist()
            check(sorted(i.filename for i in infos) == sorted(FILES),
                  "the package holds exactly the five files: %r" % sorted(i.filename for i in infos))
            for i in infos:
                check(i.compress_type == zipfile.ZIP_STORED, "%s is stored, not compressed" % i.filename)
                if i.filename in sources:
                    with open(sources[i.filename], "rb") as f:
                        check(z.read(i) == f.read(), "%s is byte for byte the built file" % i.filename)

        # The floor is the SDK's: upstream.connect first shipped in Ghost 1.2.1.
        low = run_pack(gpkg, pkg, os.path.join(tmp, "dist-low"), "1.2.0")
        check(low.returncode == 1 and "min_app_version_too_low" in (low.stdout + low.stderr),
              "the SDK refuses --min-app-version 1.2.0 for an upstream.connect plugin (rc %d: %s)"
              % (low.returncode, (low.stdout + low.stderr).strip()))

    if failures:
        print("%d check(s) FAILED" % len(failures))
        return 1
    print("packing checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
