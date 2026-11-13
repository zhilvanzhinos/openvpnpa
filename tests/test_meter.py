import concurrent.futures
import os
import subprocess
import sys
import tempfile
import unittest

from openvpnpa.meter import Meter


def total(stats):
    return sum(s["value"] for s in stats)


class MeterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "meter.sqlite")
        self.meter = Meter(self.path)

    def tearDown(self):
        self.meter.close()
        self.tmp.cleanup()

    def restart(self):
        self.meter.close()
        self.meter = Meter(self.path)

    def test_disconnect_final_sample_counts_only_unseen_tail(self):
        self.meter.sample("boot1", "client1", "42", 100, 200)
        self.assertEqual(total(self.meter.stats(reset=True)), 300)
        self.meter.sample("boot1", "client1", "42", 130, 290, final=True)
        self.assertEqual(total(self.meter.stats(reset=True)), 120)
        self.meter.sample("boot1", "client1", "42", 130, 290, final=True)
        self.assertEqual(self.meter.stats(reset=True), [])

    def test_bridge_restart_preserves_samples_and_watermarks(self):
        self.meter.sample("boot1", "client1", "42", 100, 200)
        self.restart()
        self.meter.sample("boot1", "client1", "42", 100, 200)
        self.assertEqual(total(self.meter.stats(reset=True)), 300)
        self.restart()
        self.assertEqual(self.meter.stats(reset=True), [])
        self.meter.sample("boot1", "client1", "42", 150, 300)
        self.assertEqual(total(self.meter.stats(reset=True)), 150)

    def test_process_restart_new_epoch_does_not_confuse_reused_client_id(self):
        self.meter.sample("boot1", "client1", "42", 100, 200)
        self.meter.sample("boot2", "client1", "42", 10, 20)
        self.assertEqual(total(self.meter.stats(reset=True)), 330)

    def test_closed_session_tombstone_survives_restart(self):
        self.meter.sample("boot1", "client1", "42", 100, 200, final=True)
        self.meter.stats(reset=True)
        self.restart()
        self.meter.sample("boot1", "client1", "42", 100, 200, final=True)
        self.assertEqual(self.meter.stats(), [])
        with self.assertRaises(ValueError):
            self.meter.sample("boot1", "client1", "42", 101, 201)

    def test_regression_rejected_without_changing_ledger(self):
        self.meter.sample("boot1", "client1", "42", 100, 200)
        with self.assertRaises(ValueError):
            self.meter.sample("boot1", "client1", "42", 99, 250)
        self.assertEqual(total(self.meter.stats()), 300)

    def test_owner_change_rejected(self):
        self.meter.sample("boot1", "client1", "42", 100, 200)
        with self.assertRaises(ValueError):
            self.meter.sample("boot1", "client1", "43", 150, 250)
        self.assertEqual(total(self.meter.stats()), 300)

    def test_invalid_samples_rejected(self):
        for uid, up in [("alice", 1), ("0", 1), ("42", -1), ("42", True), ("42", 2**63)]:
            with self.subTest(uid=uid, up=up), self.assertRaises(ValueError):
                self.meter.sample("boot1", "client1", uid, up, 1)
        self.assertEqual(self.meter.stats(), [])

    def test_read_without_reset_is_nondestructive(self):
        self.meter.sample("b", "c", "42", 10, 20)
        self.assertEqual(self.meter.stats(), self.meter.stats())
        self.assertEqual(total(self.meter.stats(reset=True)), 30)
        self.assertEqual(self.meter.stats(), [])

    def test_concurrent_read_reset_does_not_duplicate_local_bytes(self):
        self.meter.sample("b", "c", "42", 100, 200)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            reports = list(pool.map(lambda _: self.meter.stats(reset=True), range(16)))
        self.assertEqual(sum(map(total, reports)), 300)

    def test_abrupt_process_exit_after_commit_preserves_bytes(self):
        self.meter.close()
        proc = subprocess.run([sys.executable, "-c",
            "from openvpnpa.meter import Meter; import os,sys; "
            "m=Meter(sys.argv[1]); m.sample('b','c','42',100,200); os._exit(17)", self.path])
        self.meter = Meter(self.path)
        self.assertEqual(proc.returncode, 17)
        self.assertEqual(total(self.meter.stats(reset=True)), 300)

    def test_unobserved_tail_cannot_be_recovered_after_openvpn_crash(self):
        self.meter.sample("b", "c", "42", 100, 200)
        actual_traffic_before_crash = 350  # 50 bytes never delivered by OpenVPN
        self.restart()
        self.assertEqual(actual_traffic_before_crash-total(self.meter.stats()), 50)


if __name__ == "__main__":
    unittest.main()
