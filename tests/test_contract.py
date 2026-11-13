"""Wire-level reset fault injection plus official panel aggregation excerpts.

The HTTP fixture is deliberately plaintext on loopback in an isolated lab. It
is not a deployable node, does not advertise health, and has no panel access.
"""

import asyncio
import http.client
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from openvpnpa import service_pb2 as pb
from openvpnpa.access import AccessModel
from openvpnpa.meter import Meter
from vendor.panel_usage import _process_users_stats_response, calculate_users_usage


def wire_stats(stats):
    return pb.StatResponse(stats=[pb.Stat(**s) for s in stats])


def panel_fold(*responses):
    api_params = {index: _process_users_stats_response(response)[0]
                  for index, response in enumerate(responses)}
    return asyncio.run(calculate_users_usage(api_params, {}))


class ContractTests(unittest.TestCase):
    def test_openvpn_and_v2ray_use_same_panel_counter(self):
        openvpn = pb.StatResponse(stats=[pb.Stat(name="42", value=100), pb.Stat(name="42", value=200)])
        v2ray = pb.StatResponse(stats=[pb.Stat(name="42", value=400)])
        self.assertEqual(panel_fold(openvpn, v2ray), [{"uid": 42, "value": 700}])

    def test_openvpn_only_user_is_not_filtered_by_protocol(self):
        response = pb.StatResponse(stats=[pb.Stat(name="43", value=1234)])
        self.assertEqual(panel_fold(response), [{"uid": 43, "value": 1234}])
        # This exercises aggregation only. A real panel user/group/inbound must
        # exist for initial access sync; this does not test database integration.

    def test_coefficients_apply_to_shared_total(self):
        result = asyncio.run(calculate_users_usage(
            {1: [{"uid": 42, "value": 100}], 2: [{"uid": 42, "value": 300}]},
            {1: 2, 2: 1}))
        self.assertEqual(result, [{"uid": 42, "value": 500}])

    def test_protocol_has_no_delivery_id_or_commit_ack(self):
        self.assertEqual(set(pb.StatRequest.DESCRIPTOR.fields_by_name), {"name", "reset", "type"})
        self.assertEqual(set(pb.StatResponse.DESCRIPTOR.fields_by_name), {"stats"})
        methods = pb.DESCRIPTOR.services_by_name["NodeService"].methods_by_name
        self.assertFalse(any(name.lower().startswith(("ack", "commit")) for name in methods))

    def test_user_payload_has_no_expiry_or_remaining_quota(self):
        self.assertEqual(set(pb.User.DESCRIPTOR.fields_by_name), {"email", "proxies", "inbounds"})

    def test_expiry_removal_disconnects_in_access_model(self):
        access = AccessModel("openvpn-lab")
        access.sync_user(pb.User(email="42", inbounds=["openvpn-lab"]))
        self.assertTrue(access.connect("42"))
        # The panel expiry review would send empty inbounds. No date is sent.
        access.sync_user(pb.User(email="42"))
        self.assertIn("42", access.disconnected)
        self.assertFalse(access.connect("42"))

    def test_shared_quota_removal_disconnects_in_access_model(self):
        access = AccessModel("openvpn-lab")
        access.sync_user(pb.User(email="42", inbounds=["openvpn-lab"]))
        access.connect("42")
        usage = panel_fold(pb.StatResponse(stats=[pb.Stat(name="42", value=70)]),
                           pb.StatResponse(stats=[pb.Stat(name="42", value=40)]))
        if usage[0]["value"] >= 100:
            access.sync_user(pb.User(email="42"))
        self.assertIn("42", access.disconnected)
        self.assertFalse(access.connect("42"))

    def test_offline_node_cannot_discover_expiry_from_last_payload(self):
        access = AccessModel("openvpn-lab")
        user = pb.User(email="42", inbounds=["openvpn-lab"])
        access.sync_user(user)
        # Identical message in both worlds: user remains active / user expired
        # but revocation was lost. A local clock cannot distinguish these.
        self.assertTrue(access.connect("42"))


class ResetFaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.meter = Meter(Path(self.tmp.name)/"node.sqlite")
        self.meter.sample("boot", "session", "42", 100, 200)
        self.drop_next = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/stats/":
                    self.send_error(404)
                    return
                request = pb.StatRequest.FromString(self.rfile.read(int(self.headers["Content-Length"])))
                payload = wire_stats(fixture.meter.stats(reset=request.reset)).SerializeToString()
                if fixture.drop_next:
                    fixture.drop_next = False
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.meter.close()
        self.tmp.cleanup()

    def poll(self):
        client = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            client.request("GET", "/stats/", body=pb.StatRequest(type=pb.UsersStat, reset=True).SerializeToString())
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            return pb.StatResponse.FromString(response.read())
        finally:
            client.close()

    def test_successful_reset_retry_does_not_duplicate(self):
        self.assertEqual(panel_fold(self.poll()), [{"uid": 42, "value": 300}])
        self.assertEqual(panel_fold(self.poll()), [])

    def test_dropped_response_after_reset_loses_panel_usage(self):
        self.drop_next = True
        with self.assertRaises(http.client.RemoteDisconnected):
            self.poll()
        self.assertEqual(panel_fold(self.poll()), [])
        # Audit survives, but the panel did not receive these 300 bytes.
        self.assertEqual(sum(s["value"] for s in self.meter.audit()[0][1]), 300)

    def test_panel_crash_before_db_commit_has_same_node_state_as_success(self):
        response = self.poll()
        panel_committed_total = 0  # panel dies after receive, before DB update
        self.assertEqual(panel_fold(response), [{"uid": 42, "value": 300}])
        self.assertEqual(panel_committed_total, 0)
        self.assertEqual(panel_fold(self.poll()), [])

    def test_blind_replay_after_success_double_counts(self):
        first = self.poll()
        replay = wire_stats(self.meter.audit()[0][1])
        # The actual panel fold has no report ID to deduplicate.
        self.assertEqual(panel_fold(first, replay), [{"uid": 42, "value": 600}])


if __name__ == "__main__":
    unittest.main()
