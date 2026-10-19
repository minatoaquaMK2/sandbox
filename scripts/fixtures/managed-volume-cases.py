from __future__ import annotations

import hashlib
import json
import secrets
import signal
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


class ManagedCases:
    def initialize(self):
        sb = self.claim(mount=False)
        try:
            device = sb.exec(
                "sh",
                "-c",
                "for attempt in $(seq 1 200); do for p in /sys/block/*/serial; do "
                '[ "$(cat "$p")" = "$1" ] && { printf "/dev/%s" "$(basename "$(dirname "$p")")"; exit 0; }; '
                "done; sleep 0.01; done; exit 1",
                "volume-probe",
                self.name,
            ).strip()
            assert device.startswith("/dev/vd"), device
            sb.exec("sh", "-c", 'blkid "$1" >/dev/null 2>&1; [ "$?" = 2 ]', "volume-probe", device)
            sb.exec("sh", "-c", '! findmnt -rn -S "$1"', "volume-probe", device)
            sb.exec("mkfs.ext4", "-q", "-F", device)
            sb.exec("mkdir", "-p", "/pv-data")
            sb.exec("mount", device, "/pv-data")
            sb.write_file("/pv-data/marker", self.marker)
            sb.exec("sync", "-f", "/pv-data/marker")
            self.uuid = sb.exec("blkid", "-s", "UUID", "-o", "value", device).strip()
            assert self.uuid
            sb.exec("umount", "/pv-data")
            first_vm = self.vm(sb)
            sb.patch_volumes(add=[{"name": "catalog", "mount": "/pv-catalog"}])
            assert sb.read_file("/pv-catalog/marker").decode() == self.r.state["run_id"] + "-catalog"
            before = sb.get_volumes()
            managed = next(v for v in before["volumes"] if v["name"] == self.name)
            assert not managed.get("mount"), managed
            self.r.restart()
            assert self.vm(sb)["id"] == first_vm["id"]
            after = sb.get_volumes()
            assert after["volumes"] == before["volumes"]
            sb.exec("sh", "-c", '! findmnt -rn -S "$1"', "volume-probe", device)
            sb.patch_volumes(remove=["catalog"])
            return {
                "filesystem_uuid": self.uuid,
                "payload_bytes": len(self.marker),
                "marker_sha256": hashlib.sha256(self.marker).hexdigest(),
                "attach_only_preserved_across_live_change_and_restart": True,
                "formatted_once_explicitly": True,
            }
        finally:
            sb.close()

    def replacement(self):
        old = self.vm(self.sb)
        self.sb.close()
        self.sb = None
        assert not any(v["id"] == old["id"] for v in json.loads(self.r.cocoon("vm", "list", "--format", "json")))
        with self.claim(template="b") as sb:
            assert sb.exec("cat", "/etc/pv-template-version") == "b\n"
            current = self.vm(sb)
            assert current["id"] != old["id"]
            result = self.inspect_marker(sb)
        return {"template": "b", "old_vm": old["id"], "new_vm": current["id"], **result}

    def checkpoint(self):
        volume = self.client.get_volume(self.name)
        assert not volume.get("holders"), volume
        stat = self.disk.stat()
        self.r.state["persistent_checkpoint"] = {
            "name": self.name,
            "id": self.info["id"],
            "path": str(self.disk),
            "inode": stat.st_ino,
            "device": stat.st_dev,
            "size": stat.st_size,
            "filesystem_uuid": self.uuid,
            "payload_sha256": hashlib.sha256(self.marker).hexdigest(),
        }
        self.r.save()
        return dict(self.r.state["persistent_checkpoint"])

    def persistence(self):
        checkpoint = self.r.state["persistent_checkpoint"]
        self.name = checkpoint["name"]
        self.info = self.client.get_volume(self.name)
        self.disk = Path(checkpoint["path"])
        self.uuid = checkpoint["filesystem_uuid"]
        stat = self.disk.stat()
        assert self.info["id"] == checkpoint["id"]
        assert (stat.st_ino, stat.st_dev, stat.st_size) == (
            checkpoint["inode"],
            checkpoint["device"],
            checkpoint["size"],
        )
        with self.claim(template="b") as sb:
            result = self.inspect_marker(sb)
            assert result["marker_sha256"] == checkpoint["payload_sha256"]
        self.client.delete_volume(self.name, self.info["id"])
        return {"same_resource_and_backing_after_outer_remount": True, **result}

    def run(self):
        for case_id, action in (
            ("MV-01", self.management),
            ("MV-02", self.retries),
            ("MV-03", self.ownership),
            ("MV-04", self.deletion),
            ("MV-05", self.concurrent_management),
            ("MV-06", self.initialize),
            ("MV-07", self.warm_and_conflict),
            ("MV-08", self.restart_writer),
            ("MV-09", self.replacement),
            ("MV-10", self.release_during_attach),
            ("MV-11", self.checkpoint),
        ):
            self.r.record(case_id, action)

    def __init__(self, run):
        self.r = run
        sys.path.insert(0, str(run.args.sdk_root / "sdk/python"))
        import functools

        from cocoonsandbox import Client
        from cocoonsandbox.sandbox import Sandbox

        for method in ("exec", "read_file", "write_file"):
            original = getattr(Sandbox, method)

            def trace(original=original, method=method):
                @functools.wraps(original)
                def wrapped(sb, *args, **kwargs):
                    event = {
                        "method": method,
                        **self.r.provenance(),
                        "sandboxd_sha256": self.r.state.get("sandboxd_sha256"),
                        "sandbox_id": sb.id,
                        "arguments": [
                            value
                            if isinstance(value, str)
                            else {"sha256": hashlib.sha256(value).hexdigest()}
                            if isinstance(value, bytes)
                            else repr(value)
                            for value in args
                        ],
                    }
                    try:
                        result = original(sb, *args, **kwargs)
                        event["result"] = (
                            result
                            if isinstance(result, (str, type(None)))
                            else {"sha256": hashlib.sha256(result).hexdigest()}
                        )
                        return result
                    except Exception as exc:
                        event["error"] = str(exc)
                        raise
                    finally:
                        if self.r.case_directory:
                            with (self.r.case_directory / "guest.jsonl").open("a") as out:
                                out.write(json.dumps(event) + "\n")

                return wrapped

            setattr(Sandbox, method, trace())
        self.client_class = Client
        self.client = Client(f"127.0.0.1:{run.state['port']}", api_token=run.state["tokens"]["t1"])
        self.prefix = "pv" + secrets.token_hex(4)
        self.name = self.prefix + "main"
        self.marker = run.state["run_id"].encode() * ((4 << 20) // len(run.state["run_id"]))
        self.info = None
        self.disk = None
        self.uuid = None
        self.sb = None

    def api(self, method, path, body=None, tenant="t1", headers=None, status=200):
        actual, reply = self.r.api(method, path, body, self.r.state["tokens"].get(tenant, tenant), headers)
        assert actual == status, (method, path, actual, reply, status)
        return reply

    def path(self, name=None):
        return f"/v1/volumes/{name or self.name}"

    def create(self, name, size=1, tenant="t1", owner=None, status=201):
        body = {"size_gib": size}
        if owner is not None:
            body["tenant"] = owner
        reply = self.api("PUT", self.path(name), body, tenant, status=status)
        if status in (200, 201):
            info = reply["volume"]
            self.r.state.setdefault("volumes", {})[name] = info["id"]
            self.r.save()
            return info
        return reply

    def delete(self, name, resource_id, tenant="t1", status=204):
        return self.api(
            "DELETE", self.path(name), tenant=tenant, headers={"If-Match": f'"{resource_id}"'}, status=status
        )

    def remember(self, sb):
        self.r.state["claims"].append({"id": sb.id, "token": sb.token})
        self.r.save()
        return sb

    def claim(self, *, template="a", mount=True, mode="rw", name=None):
        volume = {"name": name or self.name, "mode": mode}
        if mount:
            volume["mount"] = "/pv-data"
        return self.remember(
            self.client.new(
                f"pv-{template}:local", net="none", size="small", ttl_seconds=1800, volumes=[volume], mount=mount
            )
        )

    def vm(self, sandbox):
        claims = json.loads((self.r.root / "state/claims.json").read_text())
        record = claims[sandbox.id]
        vms = json.loads(self.r.cocoon("vm", "list", "--format", "json"))
        return next(vm for vm in vms if vm["config"]["name"] == record["vm_name"])

    def inspect_marker(self, sb):
        assert sb.read_file("/pv-data/marker") == self.marker
        actual_uuid = sb.exec("findmnt", "-no", "UUID", "--target", "/pv-data").strip()
        assert actual_uuid == self.uuid, (actual_uuid, self.uuid)
        return {"marker_sha256": hashlib.sha256(self.marker).hexdigest(), "filesystem_uuid": actual_uuid}

    def management(self):
        before = set((self.r.root / "managed").rglob("*.raw"))
        self.info = self.create(self.name, 20)
        assert self.info["kind"] == "managed" and self.info["tenant"] == "t1"
        assert self.info["state"] == "ready" and self.info["size_bytes"] == 20 << 30
        assert self.info.get("node"), self.info
        files = set((self.r.root / "managed").rglob("*.raw")) - before
        assert len(files) == 1, files
        self.disk = files.pop()
        stat = self.disk.stat()
        assert stat.st_size == 20 << 30 and stat.st_blocks * 512 < stat.st_size
        self.r.state["managed_probe"] = {"name": self.name, "id": self.info["id"], "path": str(self.disk)}
        self.r.save()
        return {
            "volume": self.info,
            "logical_bytes": stat.st_size,
            "allocated_bytes": stat.st_blocks * 512,
            "backing_inode": stat.st_ino,
            "backing_device": stat.st_dev,
        }

    def retries(self):
        assert self.create(self.name, 20, status=200)["id"] == self.info["id"]
        before = self.disk.stat()
        self.create(self.name, 21, status=409)
        self.create(self.name, 20, tenant="root", owner="t2", status=409)
        after = self.disk.stat()
        assert (before.st_ino, before.st_size) == (after.st_ino, after.st_size)
        return {"identity": self.info["id"], "different_size_rejected": True, "different_owner_rejected": True}

    def ownership(self):
        for tenant in ("root", "t1"):
            visible = self.api("GET", "/v1/volumes", tenant=tenant)["volumes"]
            assert any(v.get("id") == self.info["id"] for v in visible)
            own = self.api("GET", self.path(), tenant=tenant)["volume"]
            assert own["tenant"] == "t1"
        visible = self.api("GET", "/v1/volumes", tenant="t2")["volumes"]
        assert not any(v.get("name") == self.name for v in visible)
        for verb in ("GET", "DELETE"):
            headers = {"If-Match": f'"{self.info["id"]}"'} if verb == "DELETE" else None
            foreign = self.api(verb, self.path(), tenant="t2", headers=headers, status=404)
            unknown = self.api(verb, self.path(self.prefix + "unknown"), tenant="t2", headers=headers, status=404)
            assert foreign == unknown, (foreign, unknown)
        self.create(self.name, 20, tenant="t2", status=404)
        self.create(self.prefix + "badowner", tenant="t1", owner="t2", status=403)
        self.create(self.prefix + "norootowner", tenant="root", status=400)
        root_volume = self.create(self.prefix + "root", tenant="root", owner="t2")
        self.delete(root_volume["name"], root_volume["id"], tenant="root")
        return {"root_and_owner_visible": True, "foreign_equals_unknown": True, "credential_derived_owner": True}

    def warm_and_conflict(self):
        self.r.ready()
        before = self.api("GET", "/v1/info", tenant="root")
        before_vms = {vm["id"] for vm in json.loads(self.r.cocoon("vm", "list", "--format", "json"))}

        def warm_count():
            request = urllib.request.Request(
                f"http://127.0.0.1:{self.r.state['port']}/metrics",
                headers={"Authorization": "Bearer " + self.r.state["tokens"]["root"]},
            )
            metrics = urllib.request.urlopen(request, timeout=10).read().decode()
            return next(
                (
                    float(line.split()[1])
                    for line in metrics.splitlines()
                    if line.startswith('sandboxd_claims_total{tier="warm"} ')
                ),
                0,
            )

        warm_before = warm_count()
        self.sb = self.claim()
        vm = self.vm(self.sb)
        warm_after = warm_count()
        assert warm_after == warm_before + 1 and vm["id"] in before_vms
        marker = self.inspect_marker(self.sb)
        status, conflict = self.r.api(
            "POST",
            "/v1/claim",
            {
                "template": "pv-a:local",
                "net": "none",
                "size": "small",
                "volumes": [{"name": self.name, "mode": "rw", "mount": "/pv-data"}],
            },
            self.r.state["tokens"]["t1"],
        )
        assert status == 409, (status, conflict)
        assert self.sb.id in json.dumps(conflict), conflict
        self.delete(self.name, self.info["id"], status=409)
        self.sb.write_file("/pv-data/second", self.marker)
        assert self.sb.read_file("/pv-data/second") == self.marker
        return {
            "id": self.sb.id,
            "vm_id": vm["id"],
            "vmm_pid": vm["pid"],
            "before_pool": before["pools"],
            "warm_metric_before": warm_before,
            "warm_metric_after": warm_after,
            "conflict": conflict,
            **marker,
        }

    def restart_writer(self):
        from importlib.util import module_from_spec, spec_from_file_location

        spec = spec_from_file_location("pv_driver", Path(__file__).resolve().parents[1] / "verify-managed-volumes.py")
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        vm = self.vm(self.sb)
        identity = module.process_identity(vm["pid"])
        results = []
        for sync in ("false", "true"):
            self.r.args.sync_claims = sync
            self.r.stop("sandboxd", signal.SIGKILL)
            self.r.restart()
            current = self.vm(self.sb)
            assert current["id"] == vm["id"] and module.process_identity(current["pid"]) == identity
            marker = self.inspect_marker(self.sb)
            status, conflict = self.r.api(
                "POST",
                "/v1/claim",
                {
                    "template": "pv-b:local",
                    "net": "none",
                    "size": "small",
                    "volumes": [{"name": self.name, "mode": "rw"}],
                },
                self.r.state["tokens"]["t1"],
            )
            assert status == 409 and self.sb.id in json.dumps(conflict), (status, conflict)
            assert self.create(self.name, 20, status=200)["id"] == self.info["id"]
            results.append({"sync_claims": sync, "same_vmm_pid_and_start": True, **marker})
        return {"restart_matrix": results}

    def deletion(self):
        name = self.prefix + "del" + secrets.token_hex(2)
        first = self.create(name)
        self.api("DELETE", self.path(name), status=428)
        self.delete(name, "wrong-id", status=412)
        self.delete(name, first["id"])
        self.delete(name, first["id"])
        self.api("GET", self.path(name), status=404)
        self.r.restart()
        self.api("GET", self.path(name), status=404)
        second = self.create(name)
        assert first["id"] != second["id"]
        self.delete(name, first["id"], status=204)
        assert self.api("GET", self.path(name))["volume"]["id"] == second["id"]
        self.delete(name, second["id"])
        return {
            "old_identity": first["id"],
            "replacement_identity": second["id"],
            "old_delete_cannot_delete_replacement": True,
        }

    def concurrent_management(self):
        name = self.prefix + "race"

        def put():
            return self.r.api("PUT", self.path(name), {"size_gib": 1}, self.r.state["tokens"]["t1"])

        with ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(lambda _: put(), range(4)))
        assert sorted(status for status, _ in replies) == [200, 200, 200, 201], replies
        ids = {reply["volume"]["id"] for _, reply in replies}
        assert len(ids) == 1
        resource_id = ids.pop()
        self.r.state.setdefault("volumes", {})[name] = resource_id
        self.r.save()
        with ThreadPoolExecutor(max_workers=2) as pool:
            creating = pool.submit(put)
            deleting = pool.submit(
                self.r.api,
                "DELETE",
                self.path(name),
                None,
                self.r.state["tokens"]["t1"],
                {"If-Match": f'"{resource_id}"'},
            )
            created, create_deleted = creating.result(), deleting.result()
        assert created[0] in (200, 201) and create_deleted[0] == 204, (created, create_deleted)
        status, final = self.r.api("GET", self.path(name), token=self.r.state["tokens"]["t1"])
        if status == 200:
            resource_id = final["volume"]["id"]
            self.r.state["volumes"][name] = resource_id
            self.r.save()
            self.delete(name, resource_id)
        else:
            assert status == 404, (status, final)
        volume = self.create(name)
        with ThreadPoolExecutor(max_workers=2) as pool:
            claiming = pool.submit(
                self.r.api,
                "POST",
                "/v1/claim",
                {
                    "template": "pv-a:local",
                    "net": "none",
                    "size": "small",
                    "volumes_attach_only": True,
                    "volumes": [{"name": name, "mode": "rw"}],
                },
                self.r.state["tokens"]["t1"],
            )
            deleting = pool.submit(
                self.r.api,
                "DELETE",
                self.path(name),
                None,
                self.r.state["tokens"]["t1"],
                {"If-Match": f'"{volume["id"]}"'},
            )
            claimed, deleted = claiming.result(), deleting.result()
        if claimed[0] == 200:
            assert deleted[0] == 409, (claimed[0], deleted)
            sb = self.remember(
                self.client.attach(f"127.0.0.1:{self.r.state['port']}", claimed[1]["id"], claimed[1]["token"])
            )
            sb.close()
            self.delete(name, volume["id"])
        else:
            assert claimed[0] in (404, 503) and deleted[0] == 204, (claimed, deleted)
        return {
            "concurrent_create_statuses": [status for status, _ in replies],
            "one_identity": resource_id,
            "create_delete_statuses": [created[0], create_deleted[0]],
            "delete_claim_statuses": [deleted[0], claimed[0]],
            "no_successful_claim_lost_backing": True,
        }

    def fault(self, name, prefix, action):
        path = self.r.root / "cocoon-fault.json"
        barrier_id = name + "-" + secrets.token_hex(4)
        path.write_text(json.dumps({"id": barrier_id, "prefix": prefix, "action": action}))
        return self.r.root / "artifacts/barriers" / barrier_id

    def wait_for(self, predicate, explanation, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError(explanation)

    def release_during_attach(self):
        sb = self.claim()
        vm = self.vm(sb)
        barrier = self.fault("release-during-attach", ["vm", "disk", "attach"], "block_after")
        removal_barrier = None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.r.state['port']}/v1/sandboxes/{sb.id}/volumes",
            method="PATCH",
            data=json.dumps({"add": [{"name": "catalog", "mount": "/pv-late"}]}).encode(),
            headers={"Authorization": "Bearer " + self.r.state["tokens"]["t1"], "Content-Type": "application/json"},
        )

        def attach():
            try:
                urllib.request.urlopen(request, timeout=30).read()
            except urllib.error.HTTPError as exc:
                (self.r.case_directory / "cancelled-attach.json").write_text(
                    json.dumps(
                        {
                            **self.r.provenance(),
                            "sandboxd_sha256": self.r.state.get("sandboxd_sha256"),
                            "status": exc.code,
                            "reply": exc.read().decode(),
                        }
                    )
                    + "\n"
                )
                return exc.code
            raise AssertionError("retiring live attach unexpectedly succeeded")

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                attaching = pool.submit(attach)
                self.wait_for(
                    lambda: (barrier / "reached.json").exists(), "live attach did not reach post-effect barrier"
                )
                removal_barrier = self.fault(
                    "release-after-cancel", ["vm", "rm", "--force", vm["config"]["name"]], "block"
                )
                releasing = pool.submit(self.r.api, "POST", f"/v1/sandboxes/{sb.id}/release", None, sb.token)
                assert attaching.result(timeout=10) in (408, 500)
                assert not (barrier / "continue").exists(), "fixture unblocked attach instead of release cancelling it"
                self.wait_for(
                    lambda: (removal_barrier / "reached.json").exists(),
                    "release did not reach removal after cancellation",
                )
                self.delete(self.name, self.info["id"], status=409)
                self.api(
                    "POST",
                    "/v1/claim",
                    {
                        "template": "pv-b:local",
                        "net": "none",
                        "size": "small",
                        "volumes_attach_only": True,
                        "volumes": [{"name": "catalog", "mode": "rw"}],
                    },
                    status=409,
                )
                assert Path(f"/proc/{vm['pid']}").exists(), "removal gate did not retain the old VMM"
                removal_barrier.joinpath("continue").touch()
                status, reply = releasing.result(timeout=30)
                assert status == 204, (status, reply)
            (self.r.root / "cocoon-fault.json").unlink(missing_ok=True)
            self.wait_for(
                lambda: not Path(f"/proc/{vm['pid']}").exists(), "released VM retained uncertain attached disk"
            )
            self.r.restart()
            with self.claim(template="b") as replacement:
                marker = self.inspect_marker(replacement)
            return {
                "release_raced_actual_readonly_attach_on_managed_vm": True,
                "release_cancelled_attach_without_client_disconnect": True,
                "managed_delete_refused_while_old_vmm_alive": True,
                "catalog_writer_refused_while_uncertain_attachment_retiring": True,
                "old_vmm_gone_before_managed_disk_reuse": True,
                **marker,
            }
        finally:
            (self.r.root / "cocoon-fault.json").unlink(missing_ok=True)
            barrier.mkdir(parents=True, exist_ok=True)
            (barrier / "continue").touch()
            if removal_barrier is not None:
                removal_barrier.mkdir(parents=True, exist_ok=True)
                (removal_barrier / "continue").touch()
