import json
import os
import struct
import tempfile
import unittest
from unittest import mock

from src.core.models import MemberInfo, SDKDump, StructInfo
from src.engines.ue import detector
from src.engines.ue.sdk_walker import (
    get_ffield_offsets_for_layout,
    score_ffield_layout_blob,
)
from src.output.dump_sanity import DumpSanityError, check_dump_dir_sanity
from src.output.health_check import run_health_check
from src.output.sdk_gen import generate_sdk


class TestUnrealDetector(unittest.TestCase):
    def test_generic_unreal_engine_cpp_string_is_unknown_not_ue4(self):
        def fake_scan(_path, needle, _section):
            if needle == "UnrealEngine":
                return [
                    (
                        0x1234,
                        r"D:\Jenkins\Ramen_HF2\Engine\Source\Runtime\Engine\Private\UnrealEngine.cpp",
                    )
                ]
            return []

        with mock.patch("src.engines.ue.detector.os.path.isfile", return_value=True), \
             mock.patch("src.engines.ue.detector.get_ue_version_from_pe", return_value=None), \
             mock.patch("src.engines.ue.detector.scan_strings_on_disk", side_effect=fake_scan):
            result = detector.detect_engine("DeadByDaylight-Win64-Shipping.exe", "fake.exe")

        self.assertEqual(result["engine"], "ue_unknown")
        self.assertEqual(result["method"], "pe_string_scan")
        self.assertIn("UnrealEngine.cpp", result["details"]["matched_string"])

    def test_back4blood_process_hint_reports_ue4_major(self):
        with mock.patch("src.engines.ue.detector.get_pid_by_name", return_value=0):
            result = detector.detect_engine("Back4Blood.exe")

        self.assertEqual(result["engine"], "ue4")
        self.assertEqual(result["version"], "")
        self.assertEqual(result["method"], "curated_process_hint")
        self.assertIn("Unreal Engine 4", result["details"]["hint"])

    def test_back4blood_generic_unreal_string_uses_curated_ue4_hint(self):
        def fake_scan(_path, needle, _section):
            if needle == "UnrealEngine":
                return [
                    (
                        0x1234,
                        r"D:\Build\Gobi\Engine\Source\Runtime\Engine\Private\UnrealEngine.cpp",
                    )
                ]
            return []

        with mock.patch("src.engines.ue.detector.os.path.isfile", return_value=True), \
             mock.patch("src.engines.ue.detector.get_ue_version_from_pe", return_value=None), \
             mock.patch("src.engines.ue.detector.scan_strings_on_disk", side_effect=fake_scan):
            result = detector.detect_engine("Back4Blood.exe", "fake.exe")

        self.assertEqual(result["engine"], "ue4")
        self.assertEqual(result["version"], "")
        self.assertEqual(result["method"], "curated_process_hint")
        self.assertEqual(result["details"]["string_scan_method"], "pe_string_scan")
        self.assertIn("UnrealEngine.cpp", result["details"]["matched_string"])


class TestFFieldLayoutScoring(unittest.TestCase):
    def _blob_for_layout(self, layout: str) -> bytes:
        offsets = get_ffield_offsets_for_layout(layout)
        raw = bytearray(0x58)
        struct.pack_into("<Q", raw, offsets["FFIELD_CLASS_PRIVATE"], 0x180000000)
        struct.pack_into("<Q", raw, offsets["FFIELD_NEXT"], 0)
        struct.pack_into("<I", raw, offsets["FFIELD_NAME"], 123)
        struct.pack_into("<i", raw, offsets["FPROPERTY_ARRAY_DIM"], 1)
        struct.pack_into("<i", raw, offsets["FPROPERTY_ELEMENT_SIZE"], 4)
        struct.pack_into("<Q", raw, offsets["FPROPERTY_FLAGS"], 0x200)
        struct.pack_into("<i", raw, offsets["FPROPERTY_OFFSET"], 0x80)
        return bytes(raw)

    def test_ue427_blob_scores_best_with_ue427_offsets(self):
        raw = self._blob_for_layout("ue427")
        ue427_score, _ = score_ffield_layout_blob(
            raw,
            get_ffield_offsets_for_layout("ue427"),
            props_size=0x200,
            field_name="Health",
            property_class_name="FloatProperty",
        )
        ue52_score, _ = score_ffield_layout_blob(
            raw,
            get_ffield_offsets_for_layout("ue52plus"),
            props_size=0x200,
            field_name="Health",
            property_class_name="FloatProperty",
        )
        self.assertGreater(ue427_score, ue52_score)

    def test_ue52plus_blob_scores_best_with_ue52plus_offsets(self):
        raw = self._blob_for_layout("ue52plus")
        ue52_score, _ = score_ffield_layout_blob(
            raw,
            get_ffield_offsets_for_layout("ue52plus"),
            props_size=0x200,
            field_name="Health",
            property_class_name="FloatProperty",
        )
        ue427_score, _ = score_ffield_layout_blob(
            raw,
            get_ffield_offsets_for_layout("ue427"),
            props_size=0x200,
            field_name="Health",
            property_class_name="FloatProperty",
        )
        self.assertGreater(ue52_score, ue427_score)


class TestDumpSanityGates(unittest.TestCase):
    def _write_dbd_like_bad_dump(self, dump_dir: str) -> None:
        entries_v2 = []
        legacy_entries = []
        for idx in range(120):
            type_name = f"BadType{idx}"
            entries_v2.append(
                {
                    "name": type_name,
                    "full_name": f"None.{type_name}",
                    "package": "None",
                    "kind": "class",
                    "size": 4,
                    "super_name": "None",
                    "members": [
                        {
                            "name": "None",
                            "offset": 0x202,
                            "storage_offset": 0x202,
                            "size": 0x200000,
                            "array_dim": 0x200000,
                            "flags": "0x7FF4C5467560",
                            "property_class": "Unknown",
                            "type": {"kind": "opaque", "display_name": "uint8_t"},
                            "bool_meta": None,
                        }
                    ],
                    "functions": [],
                }
            )
            legacy_entries.append(
                {
                    f"None.{type_name}": [
                        {"__InheritInfo": ["None"]},
                        {"__MDKClassSize": 4},
                        {"__Assembly": "None"},
                        {"None": [["Unknown", "D", "", []], 0x202, 0x200000]},
                    ]
                }
            )

        for filename in ("ClassesInfoV2.json", "StructsInfoV2.json"):
            payload = {"schema_version": 2, "kind": "ue_structs", "data": entries_v2}
            with open(os.path.join(dump_dir, filename), "w", encoding="utf-8") as handle:
                json.dump(payload, handle)

        with open(os.path.join(dump_dir, "ClassesInfo.json"), "w", encoding="utf-8") as handle:
            json.dump({"data": legacy_entries}, handle)
        with open(os.path.join(dump_dir, "StructsInfo.json"), "w", encoding="utf-8") as handle:
            json.dump({"data": []}, handle)
        with open(os.path.join(dump_dir, "EnumsInfo.json"), "w", encoding="utf-8") as handle:
            json.dump({"data": []}, handle)
        with open(os.path.join(dump_dir, "OffsetsInfo.json"), "w", encoding="utf-8") as handle:
            json.dump({"engine": "ue", "data": [["OFFSET_GWORLD", 0x1234]]}, handle)

    def test_bad_dbd_like_dump_is_blocked_before_sdk_generation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dump_dir = os.path.join(temp_dir, "Offsets")
            sdk_dir = os.path.join(temp_dir, "SDK")
            os.makedirs(dump_dir)
            self._write_dbd_like_bad_dump(dump_dir)

            report = check_dump_dir_sanity(dump_dir)
            self.assertFalse(report.ok)
            self.assertTrue(report.suspected_layout_mismatch)

            with self.assertRaises(DumpSanityError):
                generate_sdk(dump_dir, sdk_dir, engine="ue")

            self.assertFalse(os.path.exists(os.path.join(sdk_dir, "None.hpp")))

    def test_health_report_calls_out_suspected_layout_mismatch(self):
        dump = SDKDump()
        for idx in range(120):
            info = StructInfo(
                name=f"BadType{idx}",
                full_name=f"None.BadType{idx}",
                address=0,
                size=4,
                package="None",
                is_class=True,
            )
            info.members.append(
                MemberInfo(
                    name="None",
                    offset=0x202,
                    size=0x200000,
                    type_name="Unknown",
                    array_dim=0x200000,
                    flags=0x7FF4C5467560,
                )
            )
            dump.structs.append(info)

        report = run_health_check(dump, ue_version="4.27")
        self.assertEqual(report.confidence_grade, "LOW")
        self.assertTrue(report.suspected_layout_mismatch)
        self.assertIn("Suspected UE FField layout mismatch", report.confidence_reasons)


if __name__ == "__main__":
    unittest.main()
