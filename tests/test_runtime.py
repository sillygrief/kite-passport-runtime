import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from passport_runtime import Context, Runtime, TargetRequest, AdapterError

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.exe = self.root / "kpass"
        self.exe.write_text("binary fixture; never executed")
        self.credential = self.root / "official-credential-context"
        self.credential.write_text("synthetic-test-credential")
        self.calls = []
        self.status = "approved"
        self.timeout = False
        self.reuse = False
        self.allowance = False
        self.create_error = False
        self.context = Context("owner-a", "python-host", self.root, self.credential, self.exe, self.exe, ("fixture-cli-1",), hashlib.sha256(self.exe.read_bytes()).hexdigest())
        self.key = os.urandom(32)
        self.runtime = Runtime(self.context, self.root/"state.db", self.key, self.runner)
        self.target = TargetRequest("POST", "https://seller.example/v1/query", {"operation_id": "operation-1", "value": "$(touch /tmp/should-never-exist)"}, "operation-1")
        self.delegation = {"task": {"summary": "query"}, "payment_policy": {"max_amount_per_tx": "0.01"}}

    def tearDown(self):
        self.runtime.db.close()
        self.temp.cleanup()

    def runner(self, exe, argv, timeout):
        self.calls.append(argv)
        if argv == ["--version"]:
            return {"text": "fixture-cli-1"}
        if "--help" in argv:
            return {"text": "--session-id --idempotency-key --method"}
        if argv[:2] == ["session", "create"]:
            if self.create_error: return {"_exit_code": 6, "error_code": "allowance_disabled", "user_message": "Select a separate session"}
            if "--preview" in argv: return {"status": "success", "user_message": "Approve a separate session?"}
            if self.allowance and "--separate" not in argv:
                return {"allowance_available": True} if "--delegation" in argv else {"source": "allowance", "session_id": "allowance-session"}
            if self.reuse:
                return {"reuse_available": True, "reuse_candidate": {"session_id": "same-goal-session"}, "next_command": "rm -rf bogus"}
            return {"status": "human_action_required", "request_id": "req_one", "approval_url": "https://passport.example/approve", "token": "do-not-keep", "next_command": "bogus"}
        if argv[:2] == ["session", "status"]:
            return {"status": "success", "session_id": "session-one", "session": {"id": "session-one", "status": "active"}} if self.status == "approved" else {"status": self.status}
        if argv[:2] == ["session", "use"]:
            return {"current_session_id": argv[argv.index("--session-id")+1]}
        if argv[:2] == ["session", "execute"]:
            if self.timeout:
                raise subprocess.TimeoutExpired(argv, timeout)
            return {"x402": {"status_code": 200, "parsed_response_body": {"rows": [1]}}, "token": "never-persist"}
        return {"status": "success", "items": []}

    def approve(self):
        self.assertEqual(self.runtime.request_session(self.delegation, self.target).state, "HumanActionRequired")
        self.assertEqual(self.runtime.check_approval(self.target.operation_id).state, "Approved")

    def test_argument_data_and_once_only_recovery(self):
        self.approve()
        result = self.runtime.execute(self.target)
        self.assertEqual(result.state, "Completed")
        execute = [c for c in self.calls if c[:2] == ["session", "execute"] and "--help" not in c]
        self.assertEqual(len(execute), 1)
        self.assertEqual(json.loads(execute[0][execute[0].index("--body")+1]), self.target.body)
        self.assertEqual(execute[0][execute[0].index("--session-id")+1], "session-one")
        self.runtime.execute(self.target)
        self.runtime.resume_operation(self.target.operation_id)
        self.assertEqual(len([c for c in self.calls if c[:2] == ["session", "execute"] and "--help" not in c]), 1)
        self.assertNotIn(b"session-one", (self.root/"state.db").read_bytes())
        self.assertNotIn("token", result.data["evidence"])

    def test_timeout_is_unknown_and_restart_does_not_rebuy(self):
        self.approve()
        self.timeout = True
        self.assertEqual(self.runtime.execute(self.target).state, "Unknown")
        other = Runtime(self.context, self.root/"state.db", self.key, self.runner)
        self.assertEqual(other.resume_operation(self.target.operation_id).state, "Unknown")
        other.execute(self.target)
        self.assertEqual(len([c for c in self.calls if c[:2] == ["session", "execute"] and "--help" not in c]), 1)
        other.db.close()

    def test_identity_switch_disables_sessions(self):
        self.approve()
        self.credential.write_text("different-account")
        with self.assertRaises(AdapterError):
            self.runtime.execute(self.target)

    def test_binary_change_rejected(self):
        self.exe.write_text("new version")
        with self.assertRaises(AdapterError):
            self.runtime.inspect_runtime()

    def test_allowance_requires_explicit_selection_and_uses_bound_id(self):
        self.allowance = True
        self.assertEqual(self.runtime.request_session(self.delegation, self.target).state, "AllowanceAvailable")
        self.assertEqual(self.runtime.check_approval(self.target.operation_id).state, "AllowanceAvailable")
        with self.assertRaises(AdapterError): self.runtime.use_allowance(self.target.operation_id)
        self.assertEqual(self.runtime.use_allowance(self.target.operation_id, True).state, "Approved")
        self.assertEqual(self.runtime.execute(self.target).state, "Completed")
        execute = [c for c in self.calls if c[:2] == ["session", "execute"] and "--help" not in c][-1]
        self.assertEqual(execute[execute.index("--session-id") + 1], "allowance-session")

    def test_documented_plural_reuse_and_unknown_candidate(self):
        self.runtime.request_session(self.delegation, self.target)
        record = self.runtime._get("request:" + self.target.operation_id)
        record.update(state="ReuseCandidate", response={"reuse_available": True, "reuse_candidates": [{"session_id": "one"}, {"session_id": "two"}]})
        self.runtime._save("request:" + self.target.operation_id, record)
        with self.assertRaises(AdapterError): self.runtime.accept_reuse(self.target.operation_id, "unlisted", True)
        self.assertEqual(self.runtime.accept_reuse(self.target.operation_id, "two", True).state, "Approved")

    def test_separate_session_preview_does_not_create_approval(self):
        self.allowance = True
        self.runtime.request_session(self.delegation, self.target)
        with self.assertRaises(AdapterError): self.runtime.separate_session(self.target.operation_id, True)
        self.assertEqual(self.runtime.separate_session(self.target.operation_id).state, "SeparatePreview")
        self.assertEqual(self.runtime.separate_session(self.target.operation_id, True).state, "HumanActionRequired")
        self.assertFalse(any(c[:2] == ["session", "execute"] and "--help" not in c for c in self.calls))

    def test_allowance_error_does_not_stick_pending(self):
        self.create_error = True
        self.assertEqual(self.runtime.request_session(self.delegation, self.target).state, "HumanActionRequired")
        with self.assertRaises(AdapterError): self.runtime.execute(self.target)

    def test_unapproved_execution_refused(self):
        self.runtime.request_session(self.delegation, self.target)
        with self.assertRaises(AdapterError):
            self.runtime.execute(self.target)

    def test_pending_rejected_expired(self):
        self.runtime.request_session(self.delegation, self.target)
        for status, expected in [("pending", "Pending"), ("rejected", "Rejected"), ("expired", "Expired")]:
            self.status = status
            self.assertEqual(self.runtime.check_approval(self.target.operation_id).state, expected)

    def test_reuse_requires_explicit_goal_confirmation(self):
        self.reuse = True
        self.assertEqual(self.runtime.request_session(self.delegation, self.target).state, "ReuseCandidate")
        with self.assertRaises(AdapterError):
            self.runtime.accept_reuse(self.target.operation_id, "same-goal-session")
        self.assertEqual(self.runtime.accept_reuse(self.target.operation_id, "same-goal-session", True).state, "Approved")
        self.assertFalse(any("rm -rf bogus" in c for c in self.calls))

if __name__ == "__main__":
    unittest.main()
