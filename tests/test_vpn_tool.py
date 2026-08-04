import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import vpn_tool


FIXTURES = Path(__file__).parent / "fixtures"


class SubscriptionTests(unittest.TestCase):
    def test_parse_xray_json(self):
        nodes = vpn_tool.parse_subscription((FIXTURES / "subscription.json").read_text())
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["host"], "vpn.example.test")
        self.assertEqual(nodes[0]["flow"], "xtls-rprx-vision")
        self.assertEqual(vpn_tool.validation_errors(nodes[0]), [])

    def test_parse_vless_uri(self):
        nodes = vpn_tool.parse_subscription((FIXTURES / "subscription.txt").read_text())
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["name"], "Example-Reality")
        self.assertEqual(nodes[0]["fp"], "firefox")
        self.assertEqual(nodes[0]["sid"], "0123456789abcdef")

    def test_decode_base64(self):
        source = (FIXTURES / "subscription.txt").read_bytes()
        decoded = vpn_tool.decode_subscription(base64.b64encode(source))
        self.assertIn("vless://", decoded)

    def test_download_creates_backup(self):
        raw = (FIXTURES / "subscription.txt").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "subscription.sub"
            target.write_text("old")
            with mock.patch.object(vpn_tool, "download", return_value=raw):
                saved, backup, count = vpn_tool.save_subscription("https://example.test/sub", target)
            self.assertEqual(saved.read_bytes(), raw)
            self.assertEqual(backup.read_text(), "old")
            self.assertEqual(count, 1)
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_reject_non_tcp(self):
        node = vpn_tool.parse_vless_uri(
            "vless://11111111-2222-4333-8444-555555555555@example.test:443"
            "?security=reality&type=ws&sni=cdn.example.test&pbk=key&sid=abcd"
        )
        self.assertIn("transport ws вместо TCP", vpn_tool.validation_errors(node))

    def test_sing_box_outbound(self):
        node = vpn_tool.parse_subscription((FIXTURES / "subscription.json").read_text())[0]
        outbound = vpn_tool.make_outbound(node)
        self.assertEqual(outbound["type"], "vless")
        self.assertTrue(outbound["tls"]["reality"]["enabled"])
        self.assertFalse(outbound["tls"]["insecure"])
        self.assertEqual(outbound["packet_encoding"], "xudp")

    def test_parse_sing_box_json(self):
        node = vpn_tool.parse_subscription(json.dumps({
            "outbounds": [{
                "type": "vless", "tag": "sing-box", "server": "vpn.example.test",
                "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555",
                "flow": "xtls-rprx-vision", "network": "tcp", "packet_encoding": "xudp",
                "tls": {"enabled": True, "insecure": False, "server_name": "cdn.example.test",
                        "utls": {"enabled": True, "fingerprint": "firefox"},
                        "reality": {"enabled": True, "public_key": "A" * 43,
                                    "short_id": "0123456789abcdef"}},
            }]
        }))[0]
        self.assertEqual(vpn_tool.validation_errors(node), [])

    def test_reject_bad_reality_values(self):
        node = vpn_tool.parse_subscription((FIXTURES / "subscription.json").read_text())[0]
        node["uuid"] = "not-a-uuid"
        node["pbk"] = "short"
        node["sid"] = "xyz"
        errors = vpn_tool.validation_errors(node)
        self.assertIn("некорректный UUID", errors)
        self.assertIn("некорректный Reality public key", errors)
        self.assertIn("некорректный Reality short ID", errors)

    def test_homeproxy_uci(self):
        node = vpn_tool.parse_subscription((FIXTURES / "subscription.json").read_text())[0]
        output = "\n".join(vpn_tool.homeproxy_uci_lines(node, "test_node"))
        self.assertIn("homeproxy.test_node.tls_reality='1'", output)
        self.assertIn("homeproxy.test_node.packet_encoding='xudp'", output)
        self.assertNotIn("burstObservatory", output)

    def test_fixture_contains_no_reference_secrets(self):
        data = json.loads((FIXTURES / "subscription.json").read_text())
        self.assertEqual(data[0]["outbounds"][0]["settings"]["vnext"][0]["address"], "vpn.example.test")


if __name__ == "__main__":
    unittest.main()
