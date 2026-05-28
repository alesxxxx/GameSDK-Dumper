import builtins
import json
import os
import struct
import tempfile
import time
import unittest
from unittest import mock

from src.core import driver
from src.core.models import SDKDump, StructInfo
from src.engines.source2.globals import CS2GlobalResult
from src.output import json_writer
from src.output.source2_globals_writer import write_cs2_globals_header, write_cs2_globals_json


class TestDriverRegressions(unittest.TestCase):
    def tearDown(self):
        driver._cr3_cache.clear()
        if hasattr(driver._last_read_result, "value"):
            del driver._last_read_result.value

    def test_kernel_read_result_tracks_actual_bytes(self):
        result = driver.KernelReadResult(
            data=b"\x00" * 100,
            total_chunks=3,
            failed_chunks=frozenset({1}),
        )
        self.assertEqual(result.failed_byte_count(100, 40), 40)
        self.assertEqual(result.actual_byte_count(100, 40), 60)

    def test_read_memory_kernel_stashes_last_result_metadata(self):
        result = driver.KernelReadResult(
            data=b"abc",
            total_chunks=1,
            failed_chunks=frozenset({0}),
        )
        with mock.patch.object(driver, "_read_memory_kernel_command", return_value=result):
            data = driver.read_memory_kernel(123, 0x1000, 3)
        self.assertEqual(data, b"abc")
        self.assertIs(driver.get_last_kernel_read_result(), result)

    def test_find_cr3_requeries_when_process_identity_changes(self):
        driver._cr3_cache[4321] = (0xAAA0, time.monotonic(), 0x1111)
        with mock.patch.object(driver, "_g_view", 1), \
             mock.patch.object(driver, "_get_process_identity", side_effect=[0x2222, 0x2222]), \
             mock.patch.object(driver, "_send_command", return_value=True), \
             mock.patch("src.core.driver.ctypes.string_at", return_value=struct.pack("<Q", 0xBBB0)):
            cr3 = driver.find_cr3(4321)
        self.assertEqual(cr3, 0xBBB0)
        self.assertEqual(driver._cr3_cache[4321][0], 0xBBB0)
        self.assertEqual(driver._cr3_cache[4321][2], 0x2222)


class TestJsonWriterRegressions(unittest.TestCase):
    def test_write_all_uses_in_memory_legacy_entries_for_offsets(self):
        dump = SDKDump()
        dump.structs.append(
            StructInfo(
                name="Actor",
                full_name="Game.Actor",
                address=0,
                package="Game",
                size=0x8,
                is_class=True,
            )
        )

        original_open = builtins.open

        def guarded_open(file, mode="r", *args, **kwargs):
            basename = os.path.basename(os.fspath(file))
            if "r" in mode and basename in {"ClassesInfo.json", "StructsInfo.json"}:
                raise AssertionError("write_all should not re-read legacy JSON dumps")
            return original_open(file, mode, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch("builtins.open", side_effect=guarded_open):
                json_writer.write_all(
                    temp_dir,
                    dump,
                    gnames_off=0x10,
                    gobjects_off=0x20,
                    gworld_off=0x30,
                    engine="ue",
                    ue_version="5.1",
                )


class TestSource2GlobalsWriterRegressions(unittest.TestCase):
    def test_cs2_globals_writer_preserves_value_semantics(self):
        results = [
            CS2GlobalResult(
                name="dwLocalPlayerPawn",
                module="client.dll",
                rva=0x20547A0,
                absolute=0x7FFA00000000 + 0x20547A0,
                description="Local C_CSPlayerPawn pointer.",
                value_kind="address",
                value_type="C_CSPlayerPawn*",
                source_base_from="dwPrediction",
                source_field_offset=0xF0,
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            header_path = os.path.join(temp_dir, "cs2_offsets.hpp")
            json_path = os.path.join(temp_dir, "cs2_offsets.json")
            write_cs2_globals_header(header_path, results, "cs2.exe")
            write_cs2_globals_json(json_path, results, "cs2.exe")

            with open(header_path, "r", encoding="utf-8") as f:
                header = f.read()
            self.assertIn("kind=address; type=C_CSPlayerPawn*", header)
            self.assertIn("computed_from=dwPrediction+0xF0", header)

            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            item = payload["globals"]["client.dll"]["dwLocalPlayerPawn"]
            self.assertEqual(item["value_kind"], "address")
            self.assertEqual(item["value_type"], "C_CSPlayerPawn*")
            self.assertEqual(item["computed_from"]["base"], "dwPrediction")
            self.assertEqual(item["computed_from"]["field_offset_int"], 0xF0)


if __name__ == "__main__":
    unittest.main()
