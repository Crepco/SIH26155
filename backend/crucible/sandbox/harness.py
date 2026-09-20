"""Booting and probing a twin, through the Docker CLI.

Two isolated bridges with no route anywhere:

* ``crucible-mgmt`` 10.90.0.0/24 - where an administrator would sit;
* ``crucible-untrust`` 10.91.0.0/24 - where an attacker would.

The twin sits on both. A prober sits on each, because a probe has to run from
somewhere: "reachable" is meaningless without saying reachable *from where*,
and on a laptop the host cannot reach a container network directly anyway.

Both networks are created ``--internal``, so nothing in the sandbox can reach
the host, the LAN or the internet. Containers are named with a run id and torn
down in a finally block, including after a crash.

The Docker CLI is driven with subprocess rather than a Python SDK: it is one
fewer dependency to vendor into an offline bundle, and the commands are
readable in the log, which matters when the sandbox is the evidence.
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from crucible.common.errors import SandboxError
from crucible.sandbox.probes import ProbeResult
from crucible.sandbox.spec import TwinSpec

__all__ = ["Sandbox", "Twin", "docker_available"]

IMAGE = "crucible-twin:1"
MGMT_NET = "10.90.0.0/24"
UNTRUST_NET = "10.91.0.0/24"
TWIN_CONTEXT = Path(__file__).resolve().parents[3].parent / "labs" / "crucible" / "twin"
#: A twin that has not booted in this long is a failure, and a failure degrades
#: the finding to ASSERTED rather than holding up the run.
BOOT_TIMEOUT = 20.0


def _run(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """Run one docker command. A hung daemon is a failed command, not a crash.

    Everything here degrades a finding to ASSERTED rather than raising out of
    the audit: a busy or wedged Docker must not take down a report that is
    otherwise complete.
    """
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", f"timed out after {timeout:.0f}s")
    except OSError as exc:
        return subprocess.CompletedProcess(args, 125, "", str(exc))


def docker_available() -> bool:
    """Is there a Docker daemon we can actually talk to?"""
    if shutil.which("docker") is None:
        return False
    return _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=25).returncode == 0


@dataclass(slots=True)
class Twin:
    """One booted device replica."""

    name: str
    spec: TwinSpec
    mgmt_ip: str
    untrust_ip: str
    boot_ms: int = 0
    log: list[str] = field(default_factory=list)


class Sandbox:
    """A run's worth of containers and networks. Use as a context manager."""

    def __init__(self, image: str = IMAGE, run_id: str | None = None) -> None:
        self.image = image
        self.run_id = run_id or secrets.token_hex(4)
        self.mgmt_network = f"crucible-mgmt-{self.run_id}"
        self.untrust_network = f"crucible-untrust-{self.run_id}"
        self.containers: list[str] = []
        self.networks: list[str] = []
        self.log: list[str] = []

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> Sandbox:
        self._create_network(self.mgmt_network, MGMT_NET)
        self._create_network(self.untrust_network, UNTRUST_NET)
        return self

    def __exit__(self, *_exc: object) -> None:
        self.destroy()

    def destroy(self) -> None:
        """Ephemeral means ephemeral, including after a crash."""
        for container in self.containers:
            _run(["docker", "rm", "-f", container], timeout=30)
        for network in self.networks:
            _run(["docker", "network", "rm", network], timeout=30)
        self.containers.clear()
        self.networks.clear()

    def _create_network(self, name: str, subnet: str) -> None:
        result = _run(
            ["docker", "network", "create", "--internal", "--subnet", subnet, name], timeout=40
        )
        if result.returncode != 0:
            raise SandboxError(f"could not create sandbox network {name}: {result.stderr.strip()}")
        self.networks.append(name)
        self.log.append(f"network {name} {subnet} (internal)")

    # -- images ------------------------------------------------------------

    def ensure_image(self, context: Path | None = None) -> None:
        if _run(["docker", "image", "inspect", self.image], timeout=30).returncode == 0:
            return
        source = context or TWIN_CONTEXT
        if not (source / "Dockerfile").exists():
            raise SandboxError(f"no twin image and no build context at {source}")
        self.log.append(f"building {self.image} from {source}")
        built = _run(["docker", "build", "-t", self.image, str(source)], timeout=900)
        if built.returncode != 0:
            raise SandboxError(f"could not build the twin image: {built.stderr.strip()[-400:]}")

    # -- containers --------------------------------------------------------

    def boot(self, spec: TwinSpec) -> Twin:
        """Start a twin on both networks and wait for its services."""
        start = time.monotonic()
        name = f"crucible-twin-{self.run_id}"
        created = _run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--network",
                self.mgmt_network,
                "--cap-add",
                "NET_ADMIN",
                "--hostname",
                spec.hostname[:63] or "twin",
                self.image,
                "run",
            ],
            timeout=60,
        )
        if created.returncode != 0:
            raise SandboxError(f"could not create the twin: {created.stderr.strip()}")
        self.containers.append(name)
        attached = _run(["docker", "network", "connect", self.untrust_network, name], timeout=40)
        if attached.returncode != 0:
            raise SandboxError(f"could not attach the untrusted network: {attached.stderr.strip()}")

        self._write_spec(name, spec)
        started = _run(["docker", "start", name], timeout=60)
        if started.returncode != 0:
            raise SandboxError(f"the twin did not start: {started.stderr.strip()}")

        mgmt_ip = self._address(name, self.mgmt_network)
        untrust_ip = self._address(name, self.untrust_network)
        self._wait_for_services(name)
        twin = Twin(
            name=name,
            spec=spec,
            mgmt_ip=mgmt_ip,
            untrust_ip=untrust_ip,
            boot_ms=int((time.monotonic() - start) * 1000),
        )
        self.log.append(
            f"twin {name} up in {twin.boot_ms} ms  mgmt {mgmt_ip}  untrust {untrust_ip}"
        )
        return twin

    def prober(self, network: str) -> str:
        """A container to probe *from*. Same image; it only runs Python."""
        suffix = "mgmt" if network == self.mgmt_network else "untrust"
        name = f"crucible-prober-{suffix}-{self.run_id}"
        created = _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--network",
                network,
                "--entrypoint",
                "sleep",
                self.image,
                "3600",
            ],
            timeout=90,
        )
        if created.returncode != 0:
            raise SandboxError(f"could not start a prober: {created.stderr.strip()}")
        self.containers.append(name)
        self._copy_probes(name)
        return name

    def _copy_probes(self, container: str) -> None:
        """The probes run inside the sandbox, so they have to be in there."""
        module = Path(__file__).with_name("probes.py")
        runner = Path(__file__).with_name("_probe_runner.py")
        _run(["docker", "exec", container, "mkdir", "-p", "/probes"], timeout=30)
        for source, target in ((module, "/probes/probes.py"), (runner, "/probes/runner.py")):
            copied = _run(["docker", "cp", str(source), f"{container}:{target}"], timeout=60)
            if copied.returncode != 0:
                raise SandboxError(f"could not install the probes: {copied.stderr.strip()}")

    def _write_spec(self, container: str, spec: TwinSpec) -> None:
        payload = json.dumps(spec.to_dict())
        script = (
            "import json,pathlib;"
            "pathlib.Path('/twin').mkdir(parents=True, exist_ok=True);"
            f"pathlib.Path('/twin/spec.json').write_text({payload!r})"
        )
        if (
            _run(["docker", "inspect", "-f", "{{.State.Running}}", container]).stdout.strip()
            == "true"
        ):
            result = _run(["docker", "exec", container, "python3", "-c", script], timeout=40)
        else:
            # Before first start: write it with a throwaway run of the image.
            local = Path(tempfile.gettempdir()) / f"crucible-spec-{self.run_id}.json"
            local.write_text(payload, encoding="utf-8")
            result = _run(["docker", "cp", str(local), f"{container}:/twin/spec.json"], timeout=40)
        if result.returncode != 0:
            raise SandboxError(f"could not write the twin spec: {result.stderr.strip()}")

    def reconfigure(self, twin: Twin, spec: TwinSpec) -> None:
        """Apply a new posture to a running twin - what a fix looks like."""
        self._write_spec(twin.name, spec)
        result = _run(
            ["docker", "exec", twin.name, "python3", "/twin/entrypoint.py", "reconfigure"],
            timeout=60,
        )
        if result.returncode != 0:
            raise SandboxError(f"the twin would not reconfigure: {result.stderr.strip()}")
        twin.spec = spec
        time.sleep(0.6)  # let the services settle before re-probing

    # -- probing -----------------------------------------------------------

    def probe(
        self, prober: str, name: str, host: str, port: int | None = None, **kwargs: object
    ) -> ProbeResult:
        request = json.dumps({"probe": name, "host": host, "port": port, "kwargs": kwargs})
        result = _run(
            ["docker", "exec", prober, "python3", "/probes/runner.py", request], timeout=60
        )
        if result.returncode != 0:
            return ProbeResult(
                probe=name,
                target=host,
                port=port or 0,
                confirmed=False,
                detail="the probe could not run inside the sandbox",
                error=result.stderr.strip()[-300:],
            )
        try:
            return ProbeResult(**json.loads(result.stdout))
        except (ValueError, TypeError) as exc:
            return ProbeResult(
                probe=name,
                target=host,
                port=port or 0,
                confirmed=False,
                detail="the probe returned something unreadable",
                error=f"{exc}: {result.stdout[:200]}",
            )

    # -- internals ---------------------------------------------------------

    def _address(self, container: str, network: str) -> str:
        template = f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}'
        result = _run(["docker", "inspect", "-f", template, container], timeout=30)
        address = result.stdout.strip()
        if not address:
            raise SandboxError(f"{container} has no address on {network}")
        return address

    def _wait_for_services(self, container: str) -> None:
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            logs = _run(["docker", "logs", "--tail", "20", container], timeout=15).stdout
            if '"configured"' in logs:
                return
            state = _run(["docker", "inspect", "-f", "{{.State.Running}}", container]).stdout
            if state.strip() != "true":
                raise SandboxError(
                    "the twin exited during boot: "
                    + _run(["docker", "logs", container]).stderr.strip()[-300:]
                )
            time.sleep(0.4)
        raise SandboxError("the twin did not report its services within the boot timeout")
