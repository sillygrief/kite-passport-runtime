"""Inspect an explicitly configured CLI context. This example never buys anything."""
import hashlib
import os
from pathlib import Path
from passport_runtime import Runtime, Context

executable = Path(os.environ["KPASS_EXECUTABLE"])
context = Context(owner=os.environ["PASSPORT_OWNER_REF"], agent="python-host",
                  cwd=Path(os.environ["PASSPORT_WORKING_DIRECTORY"]),
                  credential_file=Path(os.environ["PASSPORT_OFFICIAL_CREDENTIAL_FILE"]),
                  kpass=executable, ksearch=Path(os.environ["KSEARCH_EXECUTABLE"]),
                  allowed_versions=(os.environ["APPROVED_KPASS_VERSION"],),
                  executable_sha256=os.environ["APPROVED_KPASS_SHA256"])
runtime = Runtime(context, Path(".data/runtime.sqlite"), bytes.fromhex(os.environ["DATA_KEY"]))
result = runtime.inspect_runtime()
print(result.state, result.data.get("version"))
