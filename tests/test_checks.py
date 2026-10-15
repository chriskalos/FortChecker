"""Basic offline fixture coverage; never depends on the test host's security setup."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortchecker.__main__ import main
from fortchecker.checks import CHECKS, System, bpf, exit_code, lockdown, secure_boot, signed_code, tpm


class ChecksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.system = System(self.root)

    def put(self, name, value):
        target = self.root / name.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value if isinstance(value, bytes) else value.encode())

    def test_missing_evidence_is_unknown_not_pass(self):
        results = [check(self.system) for check in CHECKS]
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r.status == "UNKNOWN" for r in results))
        self.assertEqual(exit_code(results), 2)

    def test_secure_boot_requires_valid_variables(self):
        base = "/sys/firmware/efi/efivars/"
        guid = "-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        self.put(base + "SecureBoot" + guid, b"\x07\0\0\0\x01")
        self.assertEqual(secure_boot(self.system).status, "UNKNOWN")
        self.put(base + "SetupMode" + guid, b"\x07\0\0\0\0")
        self.assertEqual(secure_boot(self.system).status, "PASS")
        self.put(base + "SetupMode" + guid, b"\x07\0\0\0\x01")
        self.assertEqual(secure_boot(self.system).status, "FAIL")

    def test_tpm_and_bpf_positive_and_negative(self):
        self.put("/sys/class/tpm/tpm0/tpm_version_major", "2")
        self.put("/sys/kernel/security/lsm", "lockdown,capability,bpf")
        self.assertEqual(tpm(self.system).status, "PASS")
        self.assertEqual(bpf(self.system).status, "PASS")
        self.put("/sys/kernel/security/lsm", "lockdown,notbpf")
        self.assertEqual(bpf(self.system).status, "FAIL")

    def test_lockdown_requires_explicit_boot_request(self):
        self.put("/sys/kernel/security/lockdown", "none [integrity] confidentiality")
        self.assertEqual(lockdown(self.system).status, "UNKNOWN")
        self.put("/proc/cmdline", "quiet lockdown=integrity")
        self.assertEqual(lockdown(self.system).status, "PASS")

    def test_unsigned_driver_fails_and_failure_has_priority(self):
        self.put("/sys/module/example/taint", "OE")
        self.assertEqual(signed_code(self.system).status, "FAIL")
        self.assertEqual(exit_code([check(self.system) for check in CHECKS]), 1)

    def test_json_is_clean_and_has_all_checks(self):
        output = io.StringIO()
        with patch("fortchecker.__main__.System", return_value=self.system), \
                patch("platform.system", return_value="Linux"), contextlib.redirect_stdout(output):
            code = main(["--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(len(report["checks"]), 8)
        self.assertNotIn("\x1b", output.getvalue())


if __name__ == "__main__":
    unittest.main()
