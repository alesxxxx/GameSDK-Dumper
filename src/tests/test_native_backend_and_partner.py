import json
import os
import tempfile
import unittest
import zipfile
from unittest import mock

from src.core import memory, native_backend, scanner
from src.output.share_pack import create_partner_share_pack


class FakeNativeBackend:
    available = True
    path = r"C:\fake\gamesdk_native.dll"
    load_error = ""

    def __init__(self):
        self.detached = []
        self.scatter_calls = []

    def attach(self, pid, access):
        self.pid = pid
        self.access = access
        return 0xCAFE

    def detach(self, handle):
        self.detached.append(handle)

    def read_bytes(self, handle, address, size):
        return bytes(((address + i) & 0xFF) for i in range(size))

    def scatter_read(self, handle, requests):
        self.scatter_calls.append(list(requests))
        return [
            bytes(((address + i) & 0xFF) for i in range(size))
            for address, size in requests
        ]

    def enumerate_modules(self, pid):
        return [("Game.exe", 0x140000000, 0x200000, r"C:\Games\Game.exe")]

    def get_module_info(self, pid, module_name):
        if module_name.lower() == "game.exe":
            return 0x140000000, 0x200000
        return 0, 0

    def iter_readable_regions(self, handle):
        return [(0x1000, 0x1000), (0x4000, 0x2000)]

    def scan_pattern(self, handle, module_base, module_size, pattern, max_results=50):
        return [module_base + 0x123]

    def resolve_rip(self, handle, match_address, disp_offset=3, instruction_size=7):
        return match_address + instruction_size + 0x20


class TestNativeBackendAdapter(unittest.TestCase):
    def setUp(self):
        self.old_backend = memory.get_memory_backend()
        memory.set_driver_mode(False)
        memory.set_memory_backend("win32")
        memory.clear_memory_snapshots()
        memory._native_handles.clear()

    def tearDown(self):
        memory.set_memory_backend(self.old_backend)
        memory.clear_memory_snapshots()
        memory._native_handles.clear()

    def test_memory_adapter_routes_to_mocked_native_backend(self):
        fake = FakeNativeBackend()
        with mock.patch.object(memory, "_get_native_backend", return_value=fake):
            memory.set_memory_backend("native")
            handle = memory.attach(1234)

            self.assertEqual(handle, 0xCAFE)
            self.assertEqual(memory.get_module_info(1234, "Game.exe"), (0x140000000, 0x200000))
            self.assertEqual(
                memory.enumerate_modules(1234),
                [("Game.exe", 0x140000000, 0x200000, r"C:\Games\Game.exe")],
            )
            self.assertEqual(memory.read_bytes(handle, 0x1000, 4), b"\x00\x01\x02\x03")
            self.assertEqual(
                memory.scatter_read_multiple(handle, [(0x1000, 4), (0x3000, 2)]),
                [b"\x00\x01\x02\x03", b"\x00\x01"],
            )
            self.assertEqual(list(memory.iter_readable_regions(handle)), [(0x1000, 0x1000), (0x4000, 0x2000)])

            memory.detach(handle)
            self.assertEqual(fake.detached, [0xCAFE])
            self.assertEqual(fake.scatter_calls, [[(0x1000, 4), (0x3000, 2)]])

    def test_scanner_uses_active_native_backend(self):
        fake = FakeNativeBackend()
        with mock.patch.object(memory, "_get_native_backend", return_value=fake):
            memory.set_memory_backend("native")
            self.assertEqual(scanner.scan_pattern(0xCAFE, 0x5000, 0x1000, "48 8B ??"), [0x5123])
            self.assertEqual(scanner.resolve_rip(0xCAFE, 0x7000, 3, 7), 0x7027)


class TestNativeScannerParity(unittest.TestCase):
    def tearDown(self):
        memory.clear_memory_snapshots()
        memory.set_memory_backend("win32")

    def test_buffer_scanner_matches_python_scanner_on_fixture(self):
        base = 0x400000
        data = (
            b"\x90" * 17
            + b"\x48\x8B\x05\x11\x22\x33\x44"
            + b"\x90" * 5
            + b"\x48\x8B\x05\xAA\xBB\xCC\xDD"
        )
        pattern = "48 8B 05 ?? ?? ?? ??"
        memory.add_memory_snapshot(base, data)

        python_hits = scanner.scan_pattern(0, base, len(data), pattern, max_results=10)
        native_hits = native_backend.scan_buffer(data, base, pattern, max_results=10)

        self.assertEqual(native_hits, python_hits)
        self.assertEqual(native_hits, [base + 17, base + 29])


class TestPartnerSharePack(unittest.TestCase):
    def _write_json(self, path, payload):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    def test_partner_export_writes_partner_manifest_files(self):
        with tempfile.TemporaryDirectory() as offsets_dir, tempfile.TemporaryDirectory() as packs_dir:
            self._write_json(
                os.path.join(offsets_dir, "OffsetsInfo.json"),
                {
                    "ProcessName": "Game.exe",
                    "GNames": "0x100",
                    "GObjects": "0x200",
                    "GWorld": "0x300",
                },
            )
            self._write_json(
                os.path.join(offsets_dir, "ClassesInfoV2.json"),
                {
                    "schema_version": 2,
                    "data": [
                        {
                            "name": "Player",
                            "package": "Game",
                            "size": 8,
                            "members": [
                                {
                                    "name": "Health",
                                    "offset": 0,
                                    "size": 4,
                                    "array_dim": 1,
                                    "flags": 0,
                                }
                            ],
                        }
                    ],
                },
            )
            with open(os.path.join(offsets_dir, "health.txt"), "w", encoding="utf-8") as handle:
                handle.write("Confidence: HIGH\n")

            zip_path, manifest = create_partner_share_pack(
                offsets_dir,
                game_name="Game",
                trust_status="Trusted",
                trust_reason="fixture",
                sharepacks_dir=packs_dir,
                extra_metadata={"confidence": "HIGH"},
                build_fingerprints=[
                    {
                        "module": "Game.exe",
                        "timestamp": 123,
                        "size_of_image": 0x200000,
                        "header_fingerprint": "abc",
                    }
                ],
                signatures=[{"name": "dwWorld", "pattern": "48 8B 05 ?? ?? ?? ??"}],
                health_report={"confidence": "HIGH"},
            )

            self.assertEqual(manifest["export_profile"], "partner")
            with zipfile.ZipFile(zip_path, "r") as archive:
                names = set(archive.namelist())
                self.assertIn("share_manifest.json", names)
                self.assertIn("Partner/manifest.json", names)
                self.assertIn("Partner/offsets.json", names)
                self.assertIn("Partner/health_report.json", names)
                self.assertIn("Partner/integration_notes.md", names)

                partner_manifest = json.loads(archive.read("Partner/manifest.json").decode("utf-8"))
                self.assertEqual(partner_manifest["schema_version"], 1)
                self.assertTrue(
                    partner_manifest["release_policy"]["public_release_requires_partner_approval"]
                )
                self.assertEqual(partner_manifest["build_fingerprints"][0]["module"], "Game.exe")
                self.assertEqual(partner_manifest["signatures"][0]["name"], "dwWorld")

                offsets_payload = json.loads(archive.read("Partner/offsets.json").decode("utf-8"))
                self.assertIn("OffsetsInfo.json", offsets_payload["offset_payloads"])


if __name__ == "__main__":
    unittest.main()
