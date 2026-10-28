"""No shell, no implicit current session, no automatic retry of a purchase."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import json
import os
import sqlite3
import subprocess
import uuid

class AdapterError(Exception):
    pass

@dataclass(frozen=True)
class Context:
    owner: str
    agent: str
    cwd: Path
    credential_file: Path
    kpass: Path
    ksearch: Path
    # Explicit operator-verified installed version AND binary digest. Unknown installations fail closed.
    allowed_versions: tuple[str, ...]
    executable_sha256: str

@dataclass(frozen=True)
class TargetRequest:
    method: str
    url: str
    body: dict
    operation_id: str
    headers: dict | None = None

@dataclass(frozen=True)
class Result:
    state: str
    data: dict

def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def redact(value):
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items() if not any(x in k.lower() for x in ("token", "secret", "signature", "private_key", "next_command"))}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value

class Runtime:
    def __init__(self, context: Context, database: Path, data_key: bytes, runner=None):
        self.context = context
        if len(data_key) != 32:
            raise AdapterError("32-byte data key required")
        self.cipher = AESGCM(data_key)
        self.runner = runner or self._run
        if not context.cwd.is_dir() or not context.credential_file.is_file():
            raise AdapterError("Explicit existing CLI cwd and credential context required")
        self.binding = self._binding()
        database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(database, timeout=5)
        os.chmod(database, 0o600)
        self.db.execute("CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)")
        stored = self._get("identity")
        if stored and stored["binding"] != self.binding:
            raise AdapterError("Owner, agent or credential context changed")
        self._save("identity", {"binding": self.binding})

    def _binding(self):
        return fingerprint([self.context.owner, self.context.agent, str(self.context.cwd.resolve()), hashlib.sha256(self.context.credential_file.read_bytes()).hexdigest()])

    def _guard(self):
        if self.binding != self._binding():
            raise AdapterError("Credential context changed; old sessions disabled")

    def _get(self, name):
        row = self.db.execute("SELECT ciphertext FROM records WHERE id=?", (name,)).fetchone()
        if row is None:
            return None
        b = row[0]
        return json.loads(self.cipher.decrypt(b[:12], b[12:], name.encode()))

    def _save(self, name, value):
        nonce = os.urandom(12)
        sealed = nonce + self.cipher.encrypt(nonce, json.dumps(value).encode(), name.encode())
        with self.db:
            self.db.execute("INSERT INTO records VALUES (?,?) ON CONFLICT(id) DO UPDATE SET ciphertext=excluded.ciphertext", (name, sealed))

    def _run(self, executable, argv, timeout):
        # Inherit the actual supported CLI environment; do not invent credential isolation flags.
        p = subprocess.run([str(executable), *argv], cwd=self.context.cwd, shell=False,
                           capture_output=True, text=True, timeout=timeout, check=False)
        if len(p.stdout) > 4_000_000:
            raise AdapterError("CLI output over limit")
        if argv == ["--version"] or "--help" in argv:
            return {"text": p.stdout.strip(), "exit_code": p.returncode}
        try:
            data = json.loads(p.stdout)
        except ValueError:
            raise AdapterError("CLI did not return JSON; raw output withheld") from None
        return {**data, "_exit_code": p.returncode}

    def inspect_runtime(self):
        self._guard()
        if hashlib.sha256(self.context.kpass.read_bytes()).hexdigest() != self.context.executable_sha256:
            raise AdapterError("CLI binary changed")
        version = self.runner(self.context.kpass, ["--version"], 10)["text"]
        help_text = self.runner(self.context.kpass, ["session", "execute", "--help"], 10)["text"]
        usable = version in self.context.allowed_versions and all(x in help_text for x in ("--idempotency-key", "--session-id", "--method"))
        return Result("Ready" if usable else "Blocked", {"version": version, "capabilities_verified": usable})

    def discover(self, query, example=False):
        self._guard()
        if not isinstance(query, str) or len(query) > 200:
            raise AdapterError("Invalid discovery query")
        argv = ["service", "get", query, "--output", "json"] if example else ["service", "list", "--query", query, "--output", "json"]
        response = self.runner(self.context.ksearch, argv, 30)
        return Result("Blocked" if response.get("_exit_code", 0) else "Completed", redact(response))

    @staticmethod
    def _request_state(response):
        if response.get("_exit_code", 0) or response.get("status") == "error":
            return "HumanActionRequired" if response.get("error_code", "").startswith(("allowance_", "separate_session_")) else "Blocked"
        if response.get("reuse_available"):
            return "ReuseCandidate"
        if response.get("allowance_available") or response.get("source") == "allowance":
            return "AllowanceAvailable"
        if response.get("source") == "separate" and response.get("session_id"):
            return "ExistingSessionReview"
        return "HumanActionRequired" if response.get("status") == "human_action_required" or response.get("reply_first") else "Pending" if response.get("request_id") else "Blocked"

    def request_session(self, delegation, target: TargetRequest):
        if self.inspect_runtime().state != "Ready":
            raise AdapterError("CLI not approved for payments")
        if "delegation" in delegation or not {"task", "payment_policy"} <= delegation.keys():
            raise AdapterError("Expected inner delegation")
        self._validate_target(target)
        response = self.runner(self.context.kpass, ["session", "create", "--delegation", json.dumps(delegation), "--output", "json"], 60)
        state = self._request_state(response)
        # A session returned by create is not automatically treated as approved.
        self._save("request:" + target.operation_id, {"binding": self.binding, "target": asdict(target), "delegation": delegation, "response": redact(response), "state": state})
        return Result(state, redact(response))

    def use_allowance(self, operation_id, confirmed_allowance=False):
        """Bind an already approved account allowance; never fall back from a separate session."""
        self._guard()
        record = self._get("request:" + operation_id)
        if not confirmed_allowance or not record or record["state"] != "AllowanceAvailable":
            raise AdapterError("Explicit allowance selection required")
        if self.inspect_runtime().state != "Ready":
            raise AdapterError("CLI changed")
        response = self.runner(self.context.kpass, ["session", "create", "--output", "json"], 60)
        if (response.get("_exit_code", 0) or response.get("status") == "error"
                or response.get("source") != "allowance" or not response.get("session_id")):
            record.update(state="HumanActionRequired", response=redact(response))
            self._save("request:" + operation_id, record)
            return Result(record["state"], record["response"])
        record.update(session_id=response["session_id"], funding_source="allowance", state="Approved", approval=redact(response))
        self._save("request:" + operation_id, record)
        return Result("Approved", redact(response))

    def separate_session(self, operation_id, confirmed=False):
        """Preview first. Only the caller's explicit confirmation can create a separate request."""
        self._guard()
        record = self._get("request:" + operation_id)
        if not record or record["state"] in ("Approved", "Rejected", "Expired"):
            raise AdapterError("Separate session is not available for this request")
        if confirmed and record["state"] != "SeparatePreview":
            raise AdapterError("Preview required before confirmation")
        if self.inspect_runtime().state != "Ready":
            raise AdapterError("CLI changed")
        argv = ["session", "create", "--delegation", json.dumps(record["delegation"]), "--separate", *([] if confirmed else ["--preview"]), "--output", "json"]
        response = self.runner(self.context.kpass, argv, 60)
        state = self._request_state(response) if confirmed or response.get("_exit_code", 0) or response.get("status") == "error" else "SeparatePreview"
        record.update(state=state, response=redact(response))
        self._save("request:" + operation_id, record)
        return Result(state, redact(response))

    def check_approval(self, operation_id, wait=False):
        self._guard()
        record = self._get("request:" + operation_id)
        if not record:
            raise AdapterError("Unknown approval request")
        request_id = record["response"].get("request_id")
        if not request_id:
            return Result(record["state"], record["response"])
        response = self.runner(self.context.kpass, ["session", "status", "--request-id", request_id, *(["--wait"] if wait else []), "--output", "json"], 330 if wait else 30)
        session = response.get("session", {})
        approved = (response.get("approval_status") == "approved" or response.get("status") == "approved"
                    or response.get("status") == "success" and session.get("status") == "active")
        if approved and (response.get("session_id") or session.get("session_id") or session.get("id")):
            record["session_id"] = response.get("session_id") or session.get("session_id") or session.get("id")
            record["state"] = "Approved"
        else:
            record["state"] = {"rejected": "Rejected", "expired": "Expired"}.get(response.get("approval_status", response.get("status")), "Pending")
        record["approval"] = redact(response)
        self._save("request:" + operation_id, record)
        return Result(record["state"], redact(response))

    def accept_reuse(self, operation_id, session_id, confirmed_same_goal=False):
        self._guard()
        record = self._get("request:" + operation_id)
        response = (record or {}).get("response", {})
        candidates = response.get("reuse_candidates") or [response.get("reuse_candidate", {})]
        if record and record["state"] == "ExistingSessionReview":
            candidates = [response]
        if not confirmed_same_goal or not record or record["state"] not in ("ReuseCandidate", "ExistingSessionReview") or not any(c.get("session_id") == session_id for c in candidates):
            raise AdapterError("Reuse requires explicit same-goal review")
        # Only reconstruct known argv. Never execute next_command.
        response = self.runner(self.context.kpass, ["session", "use", "--session-id", session_id, "--output", "json"], 30)
        if response.get("_exit_code", 0) or response.get("current_session_id") != session_id:
            raise AdapterError("Reuse not confirmed")
        record.update(session_id=session_id, state="Approved")
        self._save("request:" + operation_id, record)
        return Result("Approved", {"session_id": session_id})

    @staticmethod
    def _validate_target(target):
        parsed = urlsplit(target.url)
        if target.method not in ("GET", "POST", "PUT", "PATCH", "DELETE") or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.fragment:
            raise AdapterError("Invalid target")
        if not target.operation_id or target.body.get("operation_id") != target.operation_id:
            raise AdapterError("Merchant operation_id mismatch")

    def execute(self, target: TargetRequest):
        self._guard()
        self._validate_target(target)
        if self.inspect_runtime().state != "Ready":
            raise AdapterError("CLI changed")
        request = self._get("request:" + target.operation_id)
        if not request or request["state"] != "Approved" or fingerprint(request["target"]) != fingerprint(asdict(target)):
            raise AdapterError("Approved target binding required")
        operation = self._get("operation:" + target.operation_id)
        digest = fingerprint(asdict(target))
        if operation:
            if operation["request_hash"] != digest:
                raise AdapterError("Operation conflict")
            return Result(operation["state"], operation)
        operation = {"operation_id": target.operation_id, "binding": self.binding, "request_hash": digest,
                     "passport_operation_key": str(uuid.uuid4()), "session_id": request["session_id"], "state": "Unknown"}
        # INSERT OR FAIL prevents two adapter instances from purchasing the same operation.
        nonce = os.urandom(12)
        sealed = nonce + self.cipher.encrypt(nonce, json.dumps(operation).encode(), ("operation:" + target.operation_id).encode())
        try:
            with self.db:
                self.db.execute("INSERT INTO records VALUES (?,?)", ("operation:" + target.operation_id, sealed))
        except sqlite3.IntegrityError:
            return self.resume_operation(target.operation_id)
        argv = ["session", "execute", "--url", target.url, "--method", target.method, "--session-id", request["session_id"],
                "--idempotency-key", operation["passport_operation_key"], "--body", json.dumps(target.body), "--headers", json.dumps(target.headers or {}), "--output", "json"]
        try:
            response = self.runner(self.context.kpass, argv, 330)
            code = response.get("x402", {}).get("status_code")
            operation["state"] = "Completed" if isinstance(code, int) and 200 <= code < 300 else "Pending" if response.get("status") == "pending" else "Unknown"
            operation["evidence"] = redact(response)
        except (subprocess.TimeoutExpired, AdapterError):
            operation["state"] = "Unknown"
        self._save("operation:" + target.operation_id, operation)
        return Result(operation["state"], operation)

    def resume_operation(self, operation_id):
        self._guard()
        record = self._get("operation:" + operation_id)
        if not record:
            raise AdapterError("Unknown operation")
        return Result(record["state"], {**record, "recovery": "Inspect original activity/receipt and merchant artifact; no new execute was sent"})

    def activity(self):
        self._guard()
        return Result("Completed", redact(self.runner(self.context.kpass, ["activity", "--kind", "x402_payment", "--output", "json"], 30)))
