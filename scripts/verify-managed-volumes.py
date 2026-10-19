#!/usr/bin/env python3
"""Verify managed volumes using an exclusively owned runtime and persistent filesystem."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def process_identity(pid):
    try:
        return {
            "pid": pid,
            "start": Path(f"/proc/{pid}/stat").read_text().split()[21],
            "command": Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(),
        }
    except FileNotFoundError:
        return None


class Run:
    def __init__(self, args):
        if (
            not (REPO / "sandboxd/go.mod").is_file()
            or "module github.com/cocoonstack/sandbox/sandboxd" not in (REPO / "sandboxd/go.mod").read_text()
        ):
            raise RuntimeError("run this verifier from the sandbox repository; composable-cocoon is a different target")
        self.args = args
        self.root = args.run_dir.resolve()
        if self.root == Path("/") or not str(self.root).startswith("/tmp/"):
            raise RuntimeError("run directory must be an isolated directory under /tmp")
        self.manifest_path = self.root / "ownership.json"
        self.state = json.loads(self.manifest_path.read_text()) if self.manifest_path.exists() else {}
        if self.args.rootfs is None and self.state.get("rootfs"):
            self.args.rootfs = Path(self.state["rootfs"])
        if self.args.hypervisor is None:
            configured = self.state.get("hypervisor")
            cocoon_config = self.root / "cocoon.json"
            if not configured and cocoon_config.exists():
                configured = json.loads(cocoon_config.read_text()).get("ch_binary")
            configured = configured or shutil.which("cloud-hypervisor")
            self.args.hypervisor = Path(configured) if configured else None
        self.args.rootfs_layer = getattr(args, "rootfs_layer", None) or [
            Path(p) for p in self.state.get("rootfs_layers", [])
        ]
        self.case_directory = None
        self.command_log = self.root / "commands.jsonl"

    def save(self):
        self.manifest_path.write_text(json.dumps(self.state, indent=2) + "\n")
        self.manifest_path.chmod(0o600)

    def command(self, argv, *, timeout=180, cwd=None):
        actual_cwd = cwd or self.args.source_root
        result = subprocess.run([str(x) for x in argv], cwd=actual_cwd, capture_output=True, text=True, timeout=timeout)
        with self.command_log.open("a") as out:
            out.write(
                json.dumps(
                    {
                        "argv": [str(x) for x in argv],
                        "cwd": str(actual_cwd),
                        "code": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                )
                + "\n"
            )
        if result.returncode:
            raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stderr[-3000:]}")
        return result.stdout

    def sdk_digest(self):
        digest = hashlib.sha256()
        for relative in ("sdk/go", "sdk/python/cocoonsandbox"):
            directory = self.args.sdk_root / relative
            if not directory.is_dir():
                raise RuntimeError(f"SDK directory is missing: {directory}")
            for path in sorted(directory.rglob("*")):
                parts = path.relative_to(directory).parts
                if not path.is_file() or any(
                    part in {"tests", "test", "silkdtest", "examples", "__pycache__", ".pytest_cache"} for part in parts
                ):
                    continue
                if path.name.endswith("_test.go") or not (
                    path.suffix in {".go", ".py"} or path == directory / "go.mod" or path == directory / "go.sum"
                ):
                    continue
                digest.update(str(path.relative_to(self.args.sdk_root)).encode())
                digest.update(path.read_bytes())
        return digest.hexdigest()

    def provenance(self):
        verification = self.state.get("verification", {})
        return {
            "verification_attempt": verification.get("attempt"),
            "source": verification.get("source", self.state.get("source")),
            "sdk_source": verification.get("sdk_source", self.state.get("sdk_source")),
            "sdk_digest": verification.get("sdk_digest"),
            "driver_source": verification.get("driver_source"),
            "binary_vcs": verification.get("binary_vcs"),
            "fixture_sha256": verification.get("fixture_sha256"),
        }

    def cocoon(self, *args):
        return self.command([self.root / "bin/cocoon", "--config", self.root / "cocoon.json", *args])

    def api(self, method, path, body=None, token=None, headers=None):
        payload = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.state['port']}{path}",
            data=payload,
            method=method,
            headers={
                "Authorization": f"Bearer {self.state['tokens']['root'] if token is None else token}",
                "Content-Type": "application/json",
                **(headers or {}),
            },
        )
        try:
            response = urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as exc:
            response = exc
        self.last_headers = dict(response.headers)
        raw = response.read().decode()
        reply = json.loads(raw) if raw else None
        if self.case_directory:

            def redact(value):
                if isinstance(value, dict):
                    return {key: "<redacted>" if "token" in key else redact(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [redact(item) for item in value]
                return value

            with (self.case_directory / "http.jsonl").open("a") as out:
                out.write(
                    json.dumps(
                        {
                            "method": method,
                            **self.provenance(),
                            "sandboxd_sha256": self.state.get("sandboxd_sha256"),
                            "path": path,
                            "body": redact(body),
                            "status": response.status,
                            "reply": redact(reply),
                        }
                    )
                    + "\n"
                )
        return response.status, reply

    def start(self, role, argv, observed_argv=None):
        old = self.state.get("processes", {}).get(role)
        if old and process_identity(old["pid"]) == old:
            return
        log = (self.root / f"{role}.log").open("ab")
        process = subprocess.Popen([str(x) for x in argv], stdout=log, stderr=log, start_new_session=True)
        log.close()
        expected = " ".join(str(x) for x in (observed_argv or argv)) + " "
        deadline = time.monotonic() + 2
        identity = process_identity(process.pid)
        while identity is not None and identity["command"] != expected and time.monotonic() < deadline:
            time.sleep(0.01)
            identity = process_identity(process.pid)
        if identity is None or identity["command"] != expected:
            raise RuntimeError(f"owned {role} exited before its command was observed")
        self.state.setdefault("processes", {})[role] = identity
        self.save()

    def stop(self, role, sig=signal.SIGTERM):
        owned = self.state.get("processes", {}).get(role)
        if not owned:
            return
        actual = process_identity(owned["pid"])
        if actual is None:
            return
        if Path(f"/proc/{owned['pid']}/stat").read_text().split()[2] == "Z":
            return
        if actual != owned:
            raise RuntimeError(f"refusing to signal changed {role} PID")
        os.kill(owned["pid"], sig)
        for _ in range(100):
            current = process_identity(owned["pid"])
            if current is None or Path(f"/proc/{owned['pid']}/stat").read_text().split()[2] == "Z":
                return
            time.sleep(0.1)
        raise RuntimeError(f"owned {role} did not stop")

    def ready(self):
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            owned = self.state.get("processes", {}).get("sandboxd")
            if owned and process_identity(owned["pid"]) != owned:
                raise RuntimeError("owned sandboxd exited before readiness; inspect sandboxd.log")
            try:
                status, info = self.api("GET", "/v1/info")
                pools = info.get("pools", [])
                if (
                    status == 200
                    and len(pools) == 2
                    and all(p.get("golden") and p["warm"] >= p["target"] for p in pools)
                ):
                    return info
            except (OSError, ValueError):
                pass
            time.sleep(1)
        raise RuntimeError("isolated pools did not become ready; inspect sandboxd.log")

    def setup(self):
        if self.args.rootfs is None or self.args.hypervisor is None:
            raise RuntimeError("setup requires --rootfs and --hypervisor (or cloud-hypervisor on PATH)")
        if not self.state and self.root.exists() and any(self.root.iterdir()):
            raise RuntimeError("new run directory must be empty")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        (self.root / "bin").mkdir(exist_ok=True)
        (self.root / "artifacts").mkdir(exist_ok=True)
        (self.root / "managed").mkdir(exist_ok=True, mode=0o700)
        if not self.state:
            self.state = {
                "run_id": secrets.token_hex(8),
                "port": self.args.port,
                "tokens": {name: secrets.token_urlsafe(32) for name in ("root", "t1", "t2")},
                "processes": {},
                "claims": [],
                "source": self.command(["git", "rev-parse", "HEAD"]).strip(),
            }
            self.save()
        previous_config = self.root / "cocoon.json"
        prior = json.loads(previous_config.read_text()) if previous_config.exists() else {}
        self.state["rootfs"] = str(self.args.rootfs.resolve())
        self.state["rootfs_layers"] = [str(p.resolve()) for p in self.args.rootfs_layer]
        self.state["hypervisor"] = str(self.args.hypervisor.resolve())
        self.state["net_scope"] = prior.get("net_scope", self.state["run_id"][:2])
        self.state["cgroup_parent"] = prior.get("cgroup_parent", "tenant-pv-" + self.state["run_id"] + ".slice")
        self.save()
        config = {
            "root_dir": str(self.root / "runtime"),
            "run_dir": str(self.root / "run"),
            "log_dir": str(self.root / "log"),
            "ch_binary": str(self.args.hypervisor.resolve()),
            "cgroup_parent": self.state["cgroup_parent"],
            "net_scope": self.state["net_scope"],
        }
        (self.root / "cocoon.json").write_text(json.dumps(config, indent=2))
        runtime = self.args.cocoon_bin or self.state.get("cocoon_bin")
        if runtime is None:
            raise RuntimeError("setup requires --cocoon-bin pointing to the pinned runtime")
        self.state["cocoon_bin"] = str(Path(runtime).resolve())
        self.save()
        temporary = self.root / "bin/cocoon.next"
        shutil.copyfile(runtime, temporary)
        temporary.chmod(0o700)
        temporary.replace(self.root / "bin/cocoon")
        if self.args.sandboxd_bin:
            shutil.copyfile(self.args.sandboxd_bin, self.root / "bin/sandboxd")
            (self.root / "bin/sandboxd").chmod(0o700)
        else:
            self.command(["go", "build", "-o", self.root / "bin/sandboxd", "."], cwd=REPO / "sandboxd", timeout=300)
        wrapper = self.root / "bin/cocoon-owned"
        import shlex

        wrapper.write_text(
            f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
            f"{shlex.quote(str(REPO / 'scripts/fixtures/managed-volume-runtime.py'))} "
            f'{shlex.quote(str(self.root))} "$@"\n'
        )
        wrapper.chmod(0o700)
        self.start(
            "cocoond",
            [
                self.root / "bin/cocoon",
                "--config",
                self.root / "cocoon.json",
                "daemon",
                "--api-socket",
                self.root / "run/cocoond.sock",
            ],
        )
        for version in ("a", "b"):
            layer = self.root / f"template-{version}.tar"
            with tarfile.open(layer, "w") as archive:
                content = (version + "\n").encode()
                entry = tarfile.TarInfo("etc/pv-template-version")
                entry.size = len(content)
                entry.mode = 0o644
                archive.addfile(entry, io.BytesIO(content))
            self.cocoon(
                "image", "import", f"pv-{version}:local", self.args.rootfs.resolve(), *self.args.rootfs_layer, layer
            )
        fixture = self.root / "static-fixture"
        fixture.mkdir(exist_ok=True)
        (fixture / "marker").write_text(self.state["run_id"] + "-catalog")
        catalog = self.root / "catalog.raw"
        if not catalog.exists():
            with catalog.open("xb") as out:
                out.truncate(64 << 20)
            self.command(["mkfs.ext4", "-q", "-F", "-d", fixture, catalog])
        sandbox_config = {
            "listen": f"127.0.0.1:{self.state['port']}",
            "data_dir": str(self.root / "state"),
            "cocoon_bin": str(wrapper),
            "api_token": self.state["tokens"]["root"],
            "cocoond_socket": str(self.root / "run/cocoond.sock"),
            "no_direct_io": True,
            "no_balloon": True,
            "sync_claims": True,
            "refill_concurrency": 2,
            "managed_volume_dir": str(self.root / "managed"),
            "volumes": [
                {"name": "catalog", "path": str(catalog), "tenants": ["t1"], "directio": "off", "writable": True}
            ],
            "pools": [{"template": f"pv-{v}:local", "net": "none", "size": "small", "warm": 2} for v in ("a", "b")],
        }
        config_path = self.root / "sandboxd.json"
        config_path.write_text(json.dumps(sandbox_config, indent=2))
        config_path.chmod(0o600)
        self.start("sandboxd", [self.root / "bin/sandboxd", "-config", config_path])
        self.ready()
        status, _ = self.api(
            "PUT", "/v1/tenants", {"tenants": [{"name": t, "token": self.state["tokens"][t]} for t in ("t1", "t2")]}
        )
        assert status == 200, status
        print("isolated runtime ready")

    def record(self, case_id, action):
        self.assert_binding()
        directory = self.root / "artifacts" / case_id
        directory.mkdir(exist_ok=True)
        previous = [path for path in directory.iterdir() if path.is_file()]
        if previous:
            archive = self.root / "artifacts/history" / case_id / str(time.time_ns())
            archive.mkdir(parents=True)
            for path in previous:
                path.rename(archive / path.name)
        self.case_directory = directory
        try:
            evidence = action()
            self.assert_binding()
            result = {"id": case_id, "result": "Pass", "evidence": evidence}
        except Exception as exc:
            result = {"id": case_id, "result": "Fail", "error": f"{type(exc).__name__}: {exc}"}
        result.update(self.provenance())
        result["evidence_level"] = (
            evidence.get("evidence_level", "real VM and service")
            if result["result"] == "Pass"
            else "attempted real service verification"
        )
        result["sandboxd_sha256"] = self.state.get("sandboxd_sha256")
        self.case_directory = None
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"{case_id} {result['result']}")
        if result["result"] == "Fail":
            raise RuntimeError(result["error"])
        return result

    def restart(self):
        self.stop("sandboxd")
        import shlex

        wrapper = self.root / "bin/cocoon-owned"
        wrapper.write_text(
            f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
            f"{shlex.quote(str(REPO / 'scripts/fixtures/managed-volume-runtime.py'))} "
            f'{shlex.quote(str(self.root))} "$@"\n'
        )
        wrapper.chmod(0o700)
        if self.args.sandboxd_bin:
            temporary = self.root / "bin/sandboxd.next"
            shutil.copyfile(self.args.sandboxd_bin, temporary)
            temporary.chmod(0o700)
            temporary.replace(self.root / "bin/sandboxd")
        config_path = self.root / "sandboxd.json"
        config = json.loads(config_path.read_text())
        config["managed_volume_dir"] = str(self.root / "managed")
        if self.args.sync_claims is not None:
            config["sync_claims"] = self.args.sync_claims == "true"
        config_path.write_text(json.dumps(config, indent=2))
        self.state["source"] = self.command(["git", "rev-parse", "HEAD"]).strip()
        self.state["sandboxd_sha256"] = hashlib.sha256((self.root / "bin/sandboxd").read_bytes()).hexdigest()
        self.state["sdk_source"] = self.command(["git", "-C", self.args.sdk_root, "rev-parse", "HEAD"]).strip()
        self.save()
        observed = [self.root / "bin/sandboxd", "-config", config_path]
        if self.args.drop_dac:
            import shlex

            command = "exec " + " ".join(shlex.quote(str(value)) for value in observed)
            argv = ["/usr/sbin/capsh", "--drop=cap_dac_override,cap_dac_read_search", "--", "-c", command]
            self.start("sandboxd", argv, observed_argv=observed)
        else:
            self.start("sandboxd", observed)
        self.ready()

    def environment(self):
        import platform
        import socket

        sys.path.insert(0, str(self.args.sdk_root / "sdk/python"))
        from cocoonsandbox import Client

        client = Client(f"127.0.0.1:{self.state['port']}", api_token=self.state["tokens"]["t1"])
        with client.new("pv-a:local", net="none", size="small", ttl_seconds=900) as sb:
            self.state["claims"].append({"id": sb.id, "token": sb.token})
            self.save()
            kernel = sb.exec("uname", "-r").strip()
        runtime = self.root / "bin/cocoon"
        hypervisor = Path(self.state["hypervisor"])
        config = json.loads((self.root / "sandboxd.json").read_text())
        receipt = {
            **self.provenance(),
            "sandboxd_sha256": hashlib.sha256((self.root / "bin/sandboxd").read_bytes()).hexdigest(),
            "runtime_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
            "runtime_build": self.command(["go", "version", "-m", runtime]),
            "hypervisor_version": self.command([hypervisor, "--version"]).strip(),
            "hypervisor_sha256": hashlib.sha256(hypervisor.read_bytes()).hexdigest(),
            "rootfs_sha256": hashlib.sha256(Path(self.state["rootfs"]).read_bytes()).hexdigest(),
            "rootfs_layers_sha256": {
                path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                for path in self.state.get("rootfs_layers", [])
            },
            "guest_kernel": kernel,
            "host_kernel": platform.release(),
            "node": socket.gethostname(),
            "host_filesystem": self.command(["stat", "-f", "-c", "%T", self.root]).strip(),
            "templates": [json.loads(self.cocoon("image", "inspect", ref)) for ref in ("pv-a:local", "pv-b:local")],
            "sync_claims": config["sync_claims"],
            "net_scope": self.state["net_scope"],
            "cgroup_parent": self.state["cgroup_parent"],
        }
        (self.root / "artifacts/environment.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print("runtime, hypervisor, guest, templates, and filesystem receipt retained")

    def cases(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "managed_cases", REPO / "scripts/fixtures/managed-volume-cases.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.ManagedCases(self)

    def fixture_hashes(self):
        return {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (
                Path(__file__),
                REPO / "scripts/fixtures/managed-volume-cases.py",
                REPO / "scripts/fixtures/managed-volume-runtime.py",
            )
        }

    def assert_binding(self):
        expected = self.state["verification"]
        assert self.command(["git", "rev-parse", "HEAD"]).strip() == expected["driver_source"]
        assert not self.command(["git", "status", "--porcelain", "--untracked-files=no"]).strip()
        assert self.sdk_digest() == expected["sdk_digest"], "SDK changed during verification"
        assert self.fixture_hashes() == expected["fixture_sha256"], "verification fixtures changed"
        assert hashlib.sha256((self.root / "bin/sandboxd").read_bytes()).hexdigest() == self.state["sandboxd_sha256"]
        owned = self.state["processes"]["sandboxd"]
        assert process_identity(owned["pid"]) == owned
        assert (
            hashlib.sha256(Path(f"/proc/{owned['pid']}/exe").read_bytes()).hexdigest() == self.state["sandboxd_sha256"]
        )

    def verify(self):
        source = self.command(["git", "rev-parse", "HEAD"]).strip()
        dirty = self.command(["git", "status", "--porcelain", "--untracked-files=no"]).strip()
        assert not dirty, "commit reviewed source before qualifying a binary"
        build = self.command(["go", "version", "-m", self.root / "bin/sandboxd"])
        assert "path\tgithub.com/cocoonstack/sandbox/sandboxd" in build, build
        assert "vcs.revision=" + source in build and "vcs.modified=false" in build, build
        owned = self.state["processes"]["sandboxd"]
        assert process_identity(owned["pid"]) == owned
        binary_hash = hashlib.sha256((self.root / "bin/sandboxd").read_bytes()).hexdigest()
        assert hashlib.sha256(Path(f"/proc/{owned['pid']}/exe").read_bytes()).hexdigest() == binary_hash
        self.state["sandboxd_sha256"] = binary_hash
        self.state["verification"] = {
            "attempt": secrets.token_hex(16),
            "source": source,
            "sdk_source": source,
            "driver_source": source,
            "sdk_digest": self.sdk_digest(),
            "binary_vcs": [line.strip() for line in build.splitlines() if "vcs." in line],
            "fixture_sha256": self.fixture_hashes(),
        }
        self.save()
        self.environment()
        self.cases().run()

    def storage(self):
        self.assert_binding()
        if self.args.mount_receipt is None:
            raise RuntimeError("storage requires the external receipt for the exclusively owned loop mount")
        receipt_path = self.args.mount_receipt.resolve()
        assert not receipt_path.is_relative_to(self.root)
        receipt = json.loads(receipt_path.read_text())
        mount = Path(receipt["mount"])
        image = Path(receipt["image"]).resolve()
        loop = receipt["loop"]
        assert self.root.is_relative_to(mount) and mount != Path("/")
        assert not receipt_path.is_relative_to(mount)
        actual = json.loads(self.command(["losetup", "--json", loop]))["loopdevices"][0]
        assert Path(actual["back-file"]).resolve() == image, actual
        assert self.command(["findmnt", "-no", "SOURCE", "--mountpoint", mount]).strip() == loop
        assert not json.loads((self.root / "managed/registry.json").read_text()).get("holds")
        before = self.command(["blkid", "-s", "UUID", "-o", "value", loop]).strip()
        self.stop("sandboxd")
        for vm in json.loads(self.cocoon("vm", "list", "--format", "json")):
            assert vm.get("socket_path", "").startswith(str(self.root / "run") + "/"), vm
            self.cocoon("vm", "stop", "--force", vm["id"])
            self.cocoon("vm", "rm", "--force", vm["id"])
        self.stop("cocoond")
        self.command(["sync", "-f", self.root])
        self.command_log = receipt_path.with_name("storage-commands.jsonl")
        self.command(["umount", mount])
        try:
            absent = subprocess.run(["findmnt", "--mountpoint", str(mount)], capture_output=True)
            assert absent.returncode == 1, absent
            self.command(["blockdev", "--flushbufs", loop])
            check = self.command(["e2fsck", "-f", "-n", loop])
        finally:
            self.command(["mount", "-o", "nodev,nosuid", loop, mount])
            self.command_log = self.root / "commands.jsonl"
        assert self.command(["blkid", "-s", "UUID", "-o", "value", loop]).strip() == before
        proof = {
            "outer_uuid": before,
            "normal_unmount": True,
            "mount_absent_observed": True,
            "read_only_fsck": check,
            "same_loop_backing": str(image),
            "host_reboot": False,
            "power_loss": False,
        }
        receipt_path.with_name("storage-roundtrip.json").write_text(json.dumps(proof, indent=2) + "\n")
        self.start(
            "cocoond",
            [
                self.root / "bin/cocoon",
                "--config",
                self.root / "cocoon.json",
                "daemon",
                "--api-socket",
                self.root / "run/cocoond.sock",
            ],
        )
        self.restart()
        self.record("MV-12", lambda: {**proof, **self.cases().persistence()})

    def report(self):
        self.assert_binding()
        verification = self.state["verification"]
        results = [
            json.loads((self.root / "artifacts" / f"MV-{n:02d}" / "result.json").read_text()) for n in range(1, 13)
        ]
        assert all(
            r["result"] == "Pass"
            and r["verification_attempt"] == verification["attempt"]
            and r["sandboxd_sha256"] == self.state["sandboxd_sha256"]
            and all(r[key] == value for key, value in self.provenance().items())
            for r in results
        ), results
        (self.root / "artifacts/report.json").write_text(
            json.dumps(
                {
                    **self.provenance(),
                    "sandboxd_sha256": self.state["sandboxd_sha256"],
                    "cases": results,
                    "passed": len(results),
                    "failed": 0,
                },
                indent=2,
            )
            + "\n"
        )
        print(f"{len(results)} correct-repository cases passed for one binary and attempt")

    def cleanup(self):
        fault_path = self.root / "cocoon-fault.json"
        if fault_path.exists():
            fault = json.loads(fault_path.read_text())
            barrier = self.root / "artifacts/barriers" / fault["id"]
            barrier.mkdir(parents=True, exist_ok=True)
            (barrier / "continue").touch()
            fault_path.unlink()
        try:
            status, page = self.api("GET", "/v1/sandboxes")
            assert status == 200, (status, page)
            if status == 200:
                for claim in page.get("sandboxes", []):
                    code, _ = self.api("POST", f"/v1/sandboxes/{claim['id']}/release")
                    assert code in (204, 200), (claim["id"], code)
                for name, resource_id in self.state.get("volumes", {}).items():
                    deadline = time.monotonic() + 60
                    while True:
                        code, reply = self.api(
                            "DELETE", f"/v1/volumes/{name}", headers={"If-Match": f'"{resource_id}"'}
                        )
                        if code in (204, 404, 412):
                            break
                        assert code == 409 and time.monotonic() < deadline, (name, code, reply)
                        time.sleep(0.1)
                status, remaining = self.api("GET", "/v1/volumes")
                assert status == 200, (status, remaining)
                assert not [volume for volume in remaining.get("volumes", []) if volume.get("kind") == "managed"], (
                    remaining
                )
                status, remaining_claims = self.api("GET", "/v1/sandboxes")
                assert status == 200 and not remaining_claims.get("sandboxes"), (status, remaining_claims)
        except urllib.error.URLError as exc:
            raise RuntimeError(
                "restart owned sandboxd before cleanup so durable managed ownership can converge"
            ) from exc
        self.stop("sandboxd")
        vms = json.loads(self.cocoon("vm", "list", "--format", "json"))
        for vm in vms:
            socket = vm.get("socket_path", "")
            if not socket.startswith(str(self.root / "run") + "/"):
                raise RuntimeError("refusing cleanup of VM outside owned runtime")
            self.cocoon("vm", "stop", "--force", vm["id"])
            self.cocoon("vm", "rm", "--force", vm["id"])
        self.stop("cocoond")
        assert json.loads(self.cocoon("vm", "list", "--format", "json")) == []
        registry_path = self.root / "managed/registry.json"
        if registry_path.exists():
            registry = json.loads(registry_path.read_text())
            assert not registry["volumes"] and not registry["holds"], "managed resource or hold remains"
        assert not list((self.root / "managed/disks").glob("*.raw")), "managed backing remains"
        self.state["cleanup_snapshot"] = {
            "claims": 0,
            "managed_resources": 0,
            "holds": 0,
            "vms": 0,
            "managed_backing_files": 0,
            "evidence_files_retained": len(list((self.root / "artifacts").rglob("*"))),
        }
        self.save()
        print("owned runtime stopped; evidence retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("setup", "restart", "cleanup", "environment", "verify", "storage", "report")
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--rootfs-layer", type=Path, action="append")
    parser.add_argument("--hypervisor", type=Path)
    parser.add_argument("--cocoon-bin", type=Path)
    parser.add_argument("--sandboxd-bin", type=Path)
    parser.add_argument("--port", type=int, default=21777)
    parser.add_argument("--sync-claims", choices=("true", "false"))
    parser.add_argument("--drop-dac", action="store_true")
    parser.add_argument("--mount-receipt", type=Path)
    args = parser.parse_args()
    args.source_root = args.sdk_root = REPO
    os.umask(0o077)
    run = Run(args)
    getattr(run, args.command)()


if __name__ == "__main__":
    main()
