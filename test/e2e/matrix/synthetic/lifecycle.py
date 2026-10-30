#!/usr/bin/env python3
"""Private-input / UID-conditional namespace lifecycle, NOT a traffic runner.

Never use this context manager to award e2e PASS without separate traffic evidence.
Do not invoke Kubernetes through a shell, log manifests, or persist stdin JSON.
"""
import json
import importlib.util
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

CONTEXT = "k3d-ratatoskr-flannel"
LABEL = "ratatoskr.skaldhall.io/synthetic-lifecycle"
NAME = re.compile(r"rtk-syn-[0-9a-f]{16}(?:-apps)?\Z")
UID = re.compile(r"[0-9a-fA-F-]{16,64}\Z")


class LifecycleError(Exception):
    """Sanitized failure; never includes Kubernetes responses or private inputs."""


class Interrupted(LifecycleError):
    pass


def _namespace(name, token, apps):
    labels = {LABEL: token, "pod-security.kubernetes.io/enforce": "restricted" if apps else "privileged"}
    if apps:
        # Must match Gateway.allowedNamespaces selector in the synthetic fixture.
        labels["ratatoskr-synthetic"] = name.removesuffix("-apps")
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}}


class KubectlAPI:
    """Fixed argv only. Raw DELETE sends server-side UID preconditions as JSON.

    Requires a kubectl version with `delete --raw=<path> -f -` support. If
    unsupported, the call fails closed; never fall back to name-only delete.
    """
    def __init__(self, context=CONTEXT, run=subprocess.run, *, deadline=None, clock=time.monotonic):
        if context != CONTEXT:
            raise LifecycleError("Only the preflighted flannel context is allowed.")
        self.run = run
        self.deadline, self.clock = deadline, clock

    def _call(self, action, *args, obj=None, timeout=12):
        if action not in ("get", "create", "delete") or not 0 < timeout <= 15:
            raise LifecycleError("Invalid bounded Kubernetes operation.")
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - self.clock())
            if timeout <= 0:
                raise LifecycleError("Final-gate total deadline exceeded.")
        argv = ["kubectl", "--context", CONTEXT, "--request-timeout=10s", action, *args]
        # No inherited provider secrets, KUBECTL_EXTERNAL_DIFF, tracing flags,
        # locale diagnostics or process environment overrides. Kubeconfig stays
        # parent/operator-owned; never inspect it or print stdout/stderr.
        env = {key: os.environ[key] for key in ("PATH", "HOME", "KUBECONFIG") if key in os.environ}
        env["KUBECTL_KUBERC"] = "false"
        try:
            result = self.run(argv, input=None if obj is None else json.dumps(obj),
                              text=True, capture_output=True, timeout=timeout,
                              check=False, env=env)
            if result.returncode:
                raise LifecycleError("Kubernetes lifecycle operation failed (details suppressed).")
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise LifecycleError("Kubernetes lifecycle operation unavailable or timed out.") from None

    def get(self, name, timeout=12):
        if not NAME.fullmatch(name):
            raise LifecycleError("Invalid generated namespace name.")
        output = self._call("get", "namespace", name, "--ignore-not-found", "-o", "json", timeout=timeout)
        if not output.strip():
            return None
        try:
            item = json.loads(output)
            if item.get("kind") != "Namespace" or item.get("metadata", {}).get("name") != name:
                raise ValueError()
            return item
        except (ValueError, TypeError, AttributeError):
            raise LifecycleError("Namespace response is malformed.") from None

    def create(self, name, token, apps, timeout=12):
        if not NAME.fullmatch(name) or not re.fullmatch(r"[0-9a-f]{32}", token):
            raise LifecycleError("Invalid generated namespace identity.")
        output = self._call("create", "-f", "-", "-o", "json", obj=_namespace(name, token, apps), timeout=timeout)
        try:
            result = json.loads(output)
            metadata = result["metadata"]
            if (result.get("kind") != "Namespace" or metadata.get("name") != name or
                    metadata.get("labels", {}).get(LABEL) != token or
                    not isinstance(metadata.get("uid"), str) or not UID.fullmatch(metadata["uid"])):
                raise ValueError()
            return metadata["uid"]
        except (ValueError, TypeError, AttributeError, KeyError):
            raise LifecycleError("Namespace CREATE response identity is malformed; no delete authorized.") from None

    def delete_if_uid(self, name, uid, timeout=12):
        if not NAME.fullmatch(name) or not UID.fullmatch(uid):
            raise LifecycleError("Invalid namespace UID precondition.")
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid},
                   "propagationPolicy": "Foreground"}
        # Kubernetes API server performs UID comparison atomically; `delete
        # namespace <name>` alone has a replacement-namespace race.
        self._call("delete", "--raw=/api/v1/namespaces/" + name, "-f", "-",
                   obj=options, timeout=timeout)


class Lifecycle:
    """Create only freshly named namespaces; delete only exact observed UIDs.

    Overall operation deadline starts on context entry. Cleanup has its own
    bounded grace even if that deadline expires. On cleanup failure __exit__
    raises and overrides any successful body result (including a claimed PASS).
    """
    def __init__(self, api=None, *, duration=240, cleanup_budget=100,
                 clock=time.monotonic, sleep=time.sleep, make_temp=tempfile.mkdtemp,
                 token_factory=None, pki_generator=None):
        if not 0 < duration <= 900 or not 0 < cleanup_budget <= 180:
            raise LifecycleError("Invalid final-gate deadline.")
        self.api = api if api is not None else KubectlAPI()
        self.clock, self.sleep, self.make_temp = clock, sleep, make_temp
        self.duration, self.cleanup_budget = duration, cleanup_budget
        self.token = token_factory() if token_factory else uuid.uuid4().hex
        self.pki_generator = pki_generator
        if not re.fullmatch(r"[0-9a-f]{32}", self.token):
            raise LifecycleError("Invalid random namespace identity.")
        self.names = ("rtk-syn-" + self.token[:16], "rtk-syn-" + self.token[:16] + "-apps")
        self.owned = {}
        self.seen_absent = set()
        self.attempted = set()
        self.created = {}
        self.private_dir = None
        self.private_identity = None
        self.deadline = None
        self.handlers = {}
        self.closed = False

    def _time(self, deadline):
        remaining = min(12, deadline - self.clock())
        if remaining <= 0:
            raise LifecycleError("Final-gate deadline exceeded.")
        return remaining

    def _signal(self, signum, _frame):
        raise Interrupted("Final-gate interrupted; cleanup required.")

    def __enter__(self):
        if self.deadline is not None or self.closed:
            raise LifecycleError("Lifecycle cannot be re-entered.")
        if not hasattr(signal, "getsignal"):
            raise LifecycleError("Signal handlers unavailable.")
        self.deadline = self.clock() + self.duration
        # A caller-supplied API may have its own total budget, but never allow
        # this lifecycle's kubectl adapter to outlive the body deadline.
        if isinstance(self.api, KubectlAPI):
            self.api.deadline = self.deadline
        try:
            directory = Path(self.make_temp(prefix="ratatoskr-synthetic-"))
            # Remember a newly allocated path before validation, so a bad
            # TMPDIR (for example inside the repository) is still removed.
            self.private_dir = directory
            if directory.is_symlink():
                raise LifecycleError("Private input directory must not be a symlink.")
            info = directory.stat()
            self.private_identity = (info.st_dev, info.st_ino)
            repo = Path(__file__).resolve().parents[4]
            if directory.resolve().is_relative_to(repo):
                raise LifecycleError("Private input directory must be outside repository.")
            if directory.stat().st_mode & 0o777 != 0o700:
                raise LifecycleError("Private input directory must have mode 0700.")
            for sig in (signal.SIGINT, signal.SIGTERM):
                self.handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._signal)
            return self
        except BaseException as failure:
            try:
                self._finish()
            except BaseException:
                raise LifecycleError("Lifecycle entry cleanup unverified; no PASS permitted.") from None
            if isinstance(failure, LifecycleError):
                raise
            raise LifecycleError("Lifecycle entry failed (details suppressed).") from None

    def generate_pki(self):
        """Generate fixture PKI only under owned 0700 directory with umask 077.

        No key/certificate bytes are returned or printed. Key file permissions
        are checked before a caller may read them to build private manifests.
        Call only after operator authorization and release preflight.
        """
        if self.deadline is None or self.closed or self.private_dir is None:
            raise LifecycleError("Private lifecycle has not started.")
        info = self.private_dir.stat()
        if (self.private_dir.is_symlink() or
                (info.st_dev, info.st_ino) != self.private_identity or
                info.st_mode & 0o777 != 0o700 or
                self.private_dir.resolve().is_relative_to(Path(__file__).resolve().parents[4])):
            raise LifecycleError("Private input directory no longer has safe identity or mode.")
        if any(self.private_dir.iterdir()):
            raise LifecycleError("Private directory must be empty before PKI generation.")
        if self._time(self.deadline) < 1:
            raise LifecycleError("Insufficient final-gate time for PKI generation.")
        previous = os.umask(0o077)
        try:
            generator = self.pki_generator
            if generator is None:
                spec = importlib.util.spec_from_file_location("synthetic_prepare", Path(__file__).with_name("prepare.py"))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                generator = module.generate_pki
            generator(self.private_dir, deadline=self.deadline)
            for name in ("ca.key", "server.key", "client.key", "witness.key"):
                key = self.private_dir / name
                if key.is_symlink() or not key.is_file():
                    raise LifecycleError("Private PKI key is absent or unsafe.")
                if key.stat().st_mode & 0o777 != 0o600:
                    raise LifecycleError("Private PKI key mode is unsafe.")
            if self.clock() >= self.deadline:
                raise LifecycleError("Final-gate deadline expired during PKI generation.")
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, Interrupted)):
                raise
            # Never leak openssl stderr, paths or key material in exceptions.
            raise LifecycleError("Private PKI generation failed (details suppressed).") from None
        finally:
            os.umask(previous)
        return self.private_dir

    def create_namespaces(self):
        if self.deadline is None or self.closed or self.attempted:
            raise LifecycleError("Namespace lifecycle is not active or has already started.")
        # Check BOTH names before any mutation, including terminating objects.
        for name in self.names:
            if self.api.get(name, timeout=self._time(self.deadline)) is not None:
                raise LifecycleError("Generated namespace already exists; no preexisting namespace will be deleted.")
            self.seen_absent.add(name)
        for index, name in enumerate(self.names):
            self.attempted.add(name)  # Timed-out CREATE may have reached API.
            uid = self.api.create(name, self.token, index == 1, timeout=self._time(self.deadline))
            if not isinstance(uid, str) or not UID.fullmatch(uid):
                raise LifecycleError("Namespace CREATE UID unverified; refusing cleanup of unknown identity.")
            self.created[name] = uid
            obj = self.api.get(name, timeout=self._time(self.deadline))
            self._record(name, obj)
        return self.names

    def _record(self, name, obj, *, allow_deleting=False):
        meta = (obj or {}).get("metadata", {})
        uid = meta.get("uid")
        if (meta.get("name") != name or (meta.get("deletionTimestamp") and not allow_deleting) or
                meta.get("labels", {}).get(LABEL) != self.token or
                not isinstance(uid, str) or not UID.fullmatch(uid)):
            raise LifecycleError("Namespace identity/UID not verified; manual remediation may be required.")
        if name not in self.seen_absent or name not in self.attempted:
            raise LifecycleError("Namespace was not preflighted before creation attempt.")
        previous = self.owned.get(name)
        created = self.created.get(name)
        if (previous is not None and previous != uid) or (created is not None and created != uid):
            raise LifecycleError("Namespace UID changed; refusing to delete replacement.")
        # A timed-out CREATE has no confirmed response UID; label and absence
        # alone do not prove ownership after a concurrent create-name race.
        if created is None:
            raise LifecycleError("Namespace CREATE UID unverified; manual orphan inspection required.")
        self.owned[name] = uid
        return uid

    def _cleanup_namespaces(self):
        deadline = self.clock() + self.cleanup_budget
        if isinstance(self.api, KubectlAPI):
            self.api.deadline = deadline
        failures = []
        for name in reversed(self.names):
            if name not in self.attempted:
                continue  # In particular, never remove preexisting names.
            try:
                obj = self.api.get(name, timeout=self._time(deadline))
                if obj is None:
                    continue
                uid = self._record(name, obj, allow_deleting=True)
                if name not in self.owned:
                    raise LifecycleError("Namespace UID was never verified.")
                if not obj.get("metadata", {}).get("deletionTimestamp"):
                    self.api.delete_if_uid(name, uid, timeout=self._time(deadline))
                while True:
                    obj = self.api.get(name, timeout=self._time(deadline))
                    if obj is None:
                        break
                    self._record(name, obj, allow_deleting=True)  # Detect replacement during deletion.
                    self.sleep(min(1, max(0, deadline - self.clock())))
            except (LifecycleError, OSError, ValueError):
                failures.append(name)
        if failures:
            raise LifecycleError("Owned namespace cleanup unverified; operator must inspect orphaned namespaces.")

    def _finish(self):
        if self.closed:
            return
        self.closed = True
        errors = []
        try:
            for sig in self.handlers:
                signal.signal(sig, signal.SIG_IGN)  # second signal cannot bypass cleanup
            try:
                self._cleanup_namespaces()
            except BaseException:
                errors.append("namespace")
            try:
                if self.private_dir is not None:
                    if self.private_dir.is_symlink():
                        raise LifecycleError("Private directory path replaced by symlink; manual remediation required.")
                    info = self.private_dir.stat()
                    if (info.st_dev, info.st_ino) != self.private_identity:
                        raise LifecycleError("Private directory identity changed; manual remediation required.")
                    shutil.rmtree(self.private_dir)
                    if self.private_dir.exists():
                        raise LifecycleError("Private directory still exists.")
            except BaseException:
                errors.append("private input")
        finally:
            for sig, previous in self.handlers.items():
                signal.signal(sig, previous)
            self.handlers.clear()
        if errors:
            raise LifecycleError("Final-gate cleanup unverified (" + ", ".join(errors) + "); no PASS permitted.")

    def __exit__(self, exc_type, exc, tb):
        self._finish()
        if exc_type is not None and not issubclass(exc_type, (LifecycleError, KeyboardInterrupt, SystemExit)):
            # Body exceptions could contain arbitrary API objects or credentials;
            # never propagate raw exception text to the calling CLI.
            raise LifecycleError("Final-gate body failed (details suppressed).") from None
        return False
