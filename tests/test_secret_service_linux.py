"""Guard the test harness against accessing a host credential session."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import secret_service_linux as probe


class PrivateSessionTests(unittest.TestCase):
    def test_host_environment_is_not_forwarded(self):
        with patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/host/bus", "HOME": "/host/home", "DISPLAY": ":0", "UNRELATED_USER_SECRET": "private-canary"}):
            env = probe.isolated_environment(Path("/temporary/probe"))
        self.assertEqual(env["HOME"], str(Path("/temporary/probe") / "home"))
        self.assertEqual(env["DBUS_SYSTEM_BUS_ADDRESS"], "unix:path=" + str(Path("/temporary/probe") / "no-system-bus"))
        for key in ("DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "UNRELATED_USER_SECRET"):
            self.assertNotIn(key, env)

    def test_host_home_is_rejected_before_starting_a_daemon(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.dict(os.environ, {"DIRLARK_PRIVATE_KEYRING_ROOT": str(root), "HOME": "/host/home", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/host/bus"}), patch.object(probe.subprocess, "Popen") as start:
                with self.assertRaisesRegex(RuntimeError, "outside the private"):
                    probe.inside(root, Path("/unused/probe"))
                start.assert_not_called()

    def test_non_linux_refuses_real_run_before_build_or_store_access(self):
        with patch.object(sys, "platform", "darwin"), patch.object(sys, "argv", ["probe", "--answer-yes"]), patch.object(probe.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "requires Linux"):
                probe.main()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
