import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "openwrt-vless"
UUID = "11111111-2222-4333-8444-555555555555"
PUBLIC_KEY = "A" * 43


class OpenWrtAutoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.config = self.root / "homeproxy"
        self.runtime = self.root / "runtime.json"
        self.service_log = self.root / "service.log"
        self.subscription = self.root / "source.sub"
        self.output = self.root / "subscription.sub"
        self.env_file = self.root / ".env"
        self.env_file.write_text("VPN_SUBSCRIPTION_URL='https://provider.example.test/sub?token=test'\n")
        self.subscription.write_text("\n".join(
            f"vless://{UUID}@{host}:443?security=reality&type=tcp&sni=cdn.example.test"
            f"&fp=firefox&pbk={PUBLIC_KEY}&sid=0123456789abcdef#{host}"
            for host in ("bad1.example.test", "bad2.example.test", "good.example.test")
        ) + "\n")
        self.config.write_text(
            "homeproxy.config.routing_mode=bypass_mainland_china\n"
            "homeproxy.vless_auto.address=old.example.test\n"
        )
        self.original_config = self.config.read_text()
        self.write_executable("id", "#!/bin/sh\necho 0\n")
        self.write_executable("sleep", "#!/bin/sh\nexit 0\n")
        self.write_executable("sing-box", "#!/bin/sh\ncase \"$1\" in check) exit 0;; run) exec /bin/sleep 30;; esac\n")
        self.write_executable("uci", """\
            #!/usr/bin/env python3
            import os, sys
            from pathlib import Path
            path = Path(os.environ['VPN_HOMEPROXY_CONFIG'])
            args = sys.argv[1:]
            if args[0] == '-q': args = args[1:]
            command = args[0]
            if command == 'get':
                key = args[1] + '='
                values = [line[len(key):] for line in path.read_text().splitlines() if line.startswith(key)]
                if not values: sys.exit(1)
                print(values[-1])
            elif command == 'set':
                with path.open('a') as output: output.write(args[1] + '\\n')
            elif command == 'commit':
                pass
            elif command == 'show':
                print(path.read_text(), end='')
            else:
                sys.exit(2)
        """)
        self.write_executable("curl", """\
            #!/usr/bin/env python3
            import os, sys
            from pathlib import Path
            args = sys.argv[1:]
            if '-A' in args:
                if os.environ.get('VPN_TEST_DOWNLOAD_FAIL') == '1': sys.exit(22)
                target = Path(args[args.index('-o') + 1])
                target.write_bytes(Path(os.environ['VPN_TEST_SUBSCRIPTION']).read_bytes())
                sys.exit(0)
            if '--socks5-hostname' in args:
                port = int(args[args.index('--socks5-hostname') + 1].rsplit(':', 1)[1])
                index = port - 18080
                print('000\\t0\\t0' if index == 1 else
                      f'200\\t{index / 100:.2f}\\t1000', end='')
                sys.exit(0)
            config = Path(os.environ['VPN_HOMEPROXY_CONFIG']).read_text()
            good = os.environ.get('VPN_TEST_GOOD_HOST', 'good.example.test')
            print('200' if 'homeproxy.vless_auto.address=' + good in config else '000', end='')
        """)
        self.service = self.root / "service"
        self.service.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import json, os, sys
            from pathlib import Path
            action = sys.argv[1]
            with Path(os.environ['VPN_TEST_SERVICE_LOG']).open('a') as output:
                output.write(action + '\\n')
            if action == 'restart':
                lines = Path(os.environ['VPN_HOMEPROXY_CONFIG']).read_text().splitlines()
                def get(key):
                    values = [line[len(key)+1:] for line in lines if line.startswith(key + '=')]
                    return values[-1] if values else ''
                outbound = {
                    'tag': 'main-out', 'type': 'vless',
                    'server': get('homeproxy.vless_auto.address'),
                    'server_port': int(get('homeproxy.vless_auto.port') or 443),
                    'uuid': get('homeproxy.vless_auto.uuid'),
                    'tls': {'reality': {
                        'public_key': get('homeproxy.vless_auto.tls_reality_public_key'),
                        'short_id': get('homeproxy.vless_auto.tls_reality_short_id'),
                    }},
                }
                Path(os.environ['VPN_HOMEPROXY_RUNTIME_CONFIG']).write_text(
                    json.dumps({'outbounds': [outbound]}))
        """))
        self.service.chmod(0o755)

    def write_executable(self, name, source):
        path = self.bin / name
        path.write_text(textwrap.dedent(source))
        path.chmod(0o755)

    def run_auto(self, *args, good_host="good.example.test", download_fail=False):
        env = os.environ.copy()
        env.update({
            "PATH": str(self.bin) + os.pathsep + env["PATH"],
            "VPN_HOMEPROXY_CONFIG": str(self.config),
            "VPN_HOMEPROXY_SERVICE": str(self.service),
            "VPN_HOMEPROXY_RUNTIME_CONFIG": str(self.runtime),
            "VPN_TEST_SERVICE_LOG": str(self.service_log),
            "VPN_TEST_SUBSCRIPTION": str(self.subscription),
            "VPN_TEST_GOOD_HOST": good_host,
            "VPN_TEST_DOWNLOAD_FAIL": "1" if download_fail else "0",
            "VPN_AUTO_LOCK_DIR": str(self.root / "auto.lock"),
        })
        return subprocess.run(
            ["sh", str(SCRIPT), "auto", "--env-file", str(self.env_file),
             "--output", str(self.output), *args],
            text=True, capture_output=True, timeout=30, env=env, cwd=self.root,
        )

    def test_available_youtube_makes_no_changes(self):
        self.config.write_text(self.original_config.replace("old.example.test", "good.example.test"))
        result = self.run_auto()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ничего не меняем", result.stdout)
        self.assertFalse(self.service_log.exists())
        self.assertFalse(self.output.exists())

    def test_tries_next_node_and_keeps_first_working_one(self):
        result = self.run_auto()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[1/3]", result.stdout)
        self.assertIn("[2/3]", result.stdout)
        self.assertIn("[3/3]", result.stdout)
        self.assertIn("Рабочих нод: 2", result.stdout)
        self.assertIn("Пробуем ноду 2/3", result.stdout)
        self.assertIn("Пробуем ноду 3/3", result.stdout)
        self.assertNotIn("Пробуем ноду 1/3", result.stdout)
        self.assertIn("YouTube доступен; оставлена нода 3", result.stdout)
        self.assertIn("homeproxy.vless_auto.address=good.example.test", self.config.read_text())
        self.assertEqual(self.output.read_bytes(), self.subscription.read_bytes())
        self.assertEqual(self.service_log.read_text().splitlines(), ["stop", "restart", "status", "restart", "status"])
        self.assertEqual(len(list(self.root.glob("homeproxy.bak-auto-*"))), 1)

    def test_restores_original_config_when_attempts_fail(self):
        result = self.run_auto("--max", "1", good_host="never.example.test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[3/3]", result.stdout)
        self.assertEqual(self.config.read_text(), self.original_config)
        self.assertEqual(self.service_log.read_text().splitlines(), ["stop", "restart", "status", "restart"])
        self.assertIn("конфигурация восстановлена", result.stderr)

    def test_download_failure_restarts_original_homeproxy(self):
        result = self.run_auto(download_fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(), self.original_config)
        self.assertEqual(self.service_log.read_text().splitlines(), ["stop", "restart"])
        self.assertFalse((self.root / "auto.lock").exists())


if __name__ == "__main__":
    unittest.main()
