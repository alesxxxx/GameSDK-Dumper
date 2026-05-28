import struct
import unittest
from unittest import mock

from src.core.diagnostics import ScanDiagnostics
from src.engines.ue import gobjects
from src.engines.ue.signatures import get_gobjects_signatures
from src.ui.app import SDKKitApp


class TestGObjectsSignatureSelection(unittest.TestCase):
    def test_ue5_skips_legacy_gobjects_signature(self):
        names = {sig.name for sig in get_gobjects_signatures("5.5")}
        self.assertNotIn("GObjects_legacy_mov_rbx", names)
        self.assertIn("GObjects_chunked_primary", names)

    def test_ue427_skips_ue5_only_and_old_legacy_signatures(self):
        names = {sig.name for sig in get_gobjects_signatures("4.27")}
        self.assertIn("GObjects_chunked_primary", names)
        self.assertNotIn("GObjects_ue5_flat_direct", names)
        self.assertNotIn("GObjects_legacy_mov_rbx", names)

    def test_unknown_version_keeps_legacy_gobjects_signature(self):
        names = {sig.name for sig in get_gobjects_signatures("")}
        self.assertIn("GObjects_legacy_mov_rbx", names)


class TestGObjectsCandidateNormalization(unittest.TestCase):
    BASE = 0x180000

    def _shape_blob(self) -> bytes:
        raw = bytearray(0x80)
        struct.pack_into("<Q", raw, 0x10, 0x50000000)
        struct.pack_into("<iiii", raw, 0x18, 4096, 2048, 4, 1)
        return bytes(raw)

    def _read_blob(self, raw: bytes):
        def fake_read(_handle, address: int, size: int) -> bytes:
            start = address - self.BASE
            if start < 0 or start >= len(raw):
                return b""
            return raw[start : start + size]

        return fake_read

    def test_signature_targets_near_shape_recover_candidate_base(self):
        raw = self._shape_blob()
        targets = {
            "base": self.BASE,
            "objects_field": self.BASE + 0x10,
            "num_elements_field": self.BASE + 0x1C,
        }

        with mock.patch.object(gobjects, "read_bytes", side_effect=self._read_blob(raw)):
            for label, target in targets.items():
                with self.subTest(label=label):
                    candidates = gobjects._normalize_gobjects_signature_candidates(
                        None,
                        target,
                        self.BASE - 0x100,
                        0x400,
                    )
                    bases = {int(candidate["base_addr"]) for candidate in candidates}
                    self.assertIn(self.BASE, bases)


class TestGObjectsDirectArrayLayout(unittest.TestCase):
    BASE = 0x180000000
    SIZE = 0x100000
    GOBJECTS = 0x180020000
    OBJECT_ITEMS = 0x24000000000

    def setUp(self):
        gobjects.clear_gobjects_scan_state()

    @staticmethod
    def _reader(byte_map, readable_ranges):
        def fake_read(_handle, address: int, size: int) -> bytes:
            end = address + size
            if not any(start <= address and end <= stop for start, stop in readable_ranges):
                return b""
            return bytes(byte_map.get(address + off, 0) for off in range(size))

        return fake_read

    @staticmethod
    def _put_qword(byte_map, address: int, value: int) -> None:
        byte_map.update(
            {
                address + off: byte
                for off, byte in enumerate(struct.pack("<Q", value))
            }
        )

    @staticmethod
    def _put_i32(byte_map, address: int, value: int) -> None:
        byte_map.update(
            {
                address + off: byte
                for off, byte in enumerate(struct.pack("<i", value))
            }
        )

    @staticmethod
    def _read_i32(byte_map):
        def fake_read(_handle, address: int) -> int:
            data = bytes(byte_map.get(address + off, 0) for off in range(4))
            return struct.unpack("<i", data)[0]

        return fake_read

    @staticmethod
    def _read_u32(byte_map):
        def fake_read(_handle, address: int) -> int:
            data = bytes(byte_map.get(address + off, 0) for off in range(4))
            return struct.unpack("<I", data)[0]

        return fake_read

    @staticmethod
    def _read_u64(byte_map):
        def fake_read(_handle, address: int) -> int:
            data = bytes(byte_map.get(address + off, 0) for off in range(8))
            return struct.unpack("<Q", data)[0]

        return fake_read

    def _direct_fixture(self):
        byte_map = {}
        readable_ranges = [
            (self.GOBJECTS, self.GOBJECTS + 0x80),
            (self.OBJECT_ITEMS, self.OBJECT_ITEMS + 0x1000),
        ]
        self._put_qword(byte_map, self.GOBJECTS, self.OBJECT_ITEMS)
        self._put_i32(byte_map, self.GOBJECTS + 0x14, 2048)

        for index in range(12):
            obj = 0x25000000000 + index * 0x100
            cls = 0x26000000000 + index * 0x100
            readable_ranges.append((obj, obj + 0x80))
            self._put_qword(
                byte_map,
                self.OBJECT_ITEMS + index * gobjects.FUOBJECTITEM_SIZE_NORMAL,
                obj,
            )
            self._put_qword(byte_map, obj + gobjects.UOBJECT_VTABLE, self.BASE + 0x2000)
            self._put_i32(byte_map, obj + gobjects.UOBJECT_INDEX, index)
            self._put_qword(byte_map, obj + gobjects.UOBJECT_CLASS, cls)
            self._put_i32(byte_map, obj + gobjects.UOBJECT_NAME, index + 1)

        return byte_map, readable_ranges

    def test_probe_and_read_uobject_support_direct_item_arrays(self):
        byte_map, readable_ranges = self._direct_fixture()
        with mock.patch.object(
            gobjects, "read_bytes", side_effect=self._reader(byte_map, readable_ranges)
        ), mock.patch.object(
            gobjects, "read_uint64", side_effect=self._read_u64(byte_map)
        ), mock.patch.object(
            gobjects, "read_uint32", side_effect=self._read_u32(byte_map)
        ), mock.patch.object(
            gobjects, "read_int32", side_effect=self._read_i32(byte_map)
        ):
            stride = gobjects.probe_gobjects_item_size(None, self.GOBJECTS)
            self.assertEqual(stride, gobjects.FUOBJECTITEM_SIZE_NORMAL)
            self.assertEqual(gobjects.get_gobjects_objects_mode(self.GOBJECTS), "direct")
            self.assertTrue(gobjects.validate_gobjects(None, self.GOBJECTS, item_size=stride))
            obj = gobjects.read_uobject(None, self.GOBJECTS, 3, stride)

        self.assertIsNotNone(obj)
        self.assertEqual(obj["internal_index"], 3)
        self.assertEqual(obj["name_index"], 4)

    def test_brute_scan_scores_direct_item_arrays(self):
        byte_map, readable_ranges = self._direct_fixture()
        section = bytearray(0x2000)
        base_rel = 0x800
        struct.pack_into("<Q", section, base_rel + 0x10, self.OBJECT_ITEMS)
        struct.pack_into("<iiii", section, base_rel + 0x18, 4096, 2048, 1, 1)
        for off, byte in enumerate(section):
            byte_map[self.BASE + off] = byte
        readable_ranges.append((self.BASE, self.BASE + len(section)))

        with mock.patch.object(
            gobjects, "read_bytes", side_effect=self._reader(byte_map, readable_ranges)
        ), mock.patch.object(
            gobjects, "read_int32", side_effect=self._read_i32(byte_map)
        ), mock.patch(
            "src.core.memory.prefetch_memory_pages", return_value=None
        ):
            result = gobjects._find_gobjects_brute_inner_buffered(
                None,
                self.BASE,
                self.SIZE,
                [(self.BASE, self.BASE + len(section))],
            )

        self.assertEqual(result, (self.BASE + base_rel, gobjects.FUOBJECTITEM_SIZE_NORMAL))
        self.assertEqual(gobjects.get_gobjects_objects_mode(self.BASE + base_rel), "direct")

    def test_brute_scan_follows_heap_pointer_globals(self):
        byte_map, readable_ranges = self._direct_fixture()
        heap_gobjects = 0x27000000000
        section = bytearray(0x2000)
        struct.pack_into("<Q", section, 0x900, heap_gobjects)
        for off, byte in enumerate(section):
            byte_map[self.BASE + off] = byte
        readable_ranges.append((self.BASE, self.BASE + len(section)))

        readable_ranges.append((heap_gobjects, heap_gobjects + 0x80))
        self._put_qword(byte_map, heap_gobjects + 0x10, self.OBJECT_ITEMS)
        self._put_i32(byte_map, heap_gobjects + 0x18, 4096)
        self._put_i32(byte_map, heap_gobjects + 0x1C, 2048)
        self._put_i32(byte_map, heap_gobjects + 0x20, 1)
        self._put_i32(byte_map, heap_gobjects + 0x24, 1)

        reader = self._reader(byte_map, readable_ranges)

        def fake_scatter(_handle, requests):
            return [reader(_handle, address, size) for address, size in requests]

        with mock.patch.object(
            gobjects, "read_bytes", side_effect=reader
        ), mock.patch.object(
            gobjects, "read_int32", side_effect=self._read_i32(byte_map)
        ), mock.patch(
            "src.core.memory.prefetch_memory_pages", return_value=None
        ), mock.patch(
            "src.core.memory.scatter_read_multiple", side_effect=fake_scatter
        ):
            result = gobjects._find_gobjects_brute_inner_buffered(
                None,
                self.BASE,
                self.SIZE,
                [(self.BASE, self.BASE + len(section))],
            )

        self.assertEqual(result, (heap_gobjects, gobjects.FUOBJECTITEM_SIZE_NORMAL))
        self.assertEqual(gobjects.get_gobjects_objects_mode(heap_gobjects), "direct")


class TestGObjectsFailureMetadata(unittest.TestCase):
    def test_live_miss_records_signature_and_structural_failure(self):
        diag = ScanDiagnostics()

        def fake_brute(_handle, _base, _size):
            gobjects._gobjects_brute_last_meta.clear()
            gobjects._gobjects_brute_last_meta.update(
                {
                    "candidate_count": 0,
                    "stage2_count": 0,
                    "scored_count": 0,
                    "timed_out": 0,
                }
            )
            return 0, 0

        gobjects.clear_gobjects_scan_state()
        with mock.patch.object(gobjects, "load_game_offsets_override", return_value=None), \
             mock.patch.object(gobjects, "read_bytes", return_value=b""), \
             mock.patch.object(gobjects, "find_gobjects_brute", side_effect=fake_brute), \
             mock.patch("src.core.memory.USE_DRIVER", False), \
             mock.patch("src.core.pe_parser.get_pe_text_scan_ranges", return_value=[]), \
             mock.patch("src.engines.ue.gnames.find_gnames", return_value=(0, False)), \
             mock.patch("src.engines.ue.gnames.get_last_gnames_resolution_meta", return_value={}):
            result = gobjects.find_gobjects(
                None,
                0x100000,
                0x4000,
                "5.5",
                diag=diag,
            )

        self.assertEqual(result, (0, 0))
        meta = gobjects.get_last_gobjects_resolution_meta()
        self.assertEqual(meta["failure_kind"], "signature_and_structural_miss")
        self.assertEqual(meta["signature_failure_kind"], "signature_miss")
        self.assertEqual(meta["structural_failure_kind"], "structural_candidate_miss")
        self.assertEqual(meta["signature_hit_count"], 0)
        self.assertTrue(meta["names_seeded"]["attempted"])
        self.assertFalse(meta["names_seeded"]["gnames_recovered"])


class TestGObjectsDiagnosticsAndRetries(unittest.TestCase):
    def test_kernel_live_diagnostic_does_not_recommend_cached_offsets(self):
        diag = ScanDiagnostics()
        diag.info(
            "Kernel live scan skips cached GObjects/GNames OffsetsInfo overrides.",
            "GObjects",
        )
        diag.failed("GObjects", "AOB signatures", "0 hits")

        report = "\n".join(diag.format_report())
        self.assertIn("Kernel live scans do not use cached GObjects/GNames offsets.", report)
        self.assertNotIn("Try adding the game's known offsets", report)

    def test_gobjects_failure_stops_later_timeout_profiles(self):
        self.assertFalse(
            SDKKitApp._should_continue_offset_scan_retries(
                {"code": "gobjects_not_found"}
            )
        )
        self.assertTrue(
            SDKKitApp._should_continue_offset_scan_retries(
                {"code": "gworld_timeout"}
            )
        )


if __name__ == "__main__":
    unittest.main()
