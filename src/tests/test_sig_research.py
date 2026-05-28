import json
import os
import tempfile
import unittest

from src.re.cs2_catalog import extended_entries, get_catalog_entries
from src.re.pack_parser import parse_signature_pack
from src.re.signatures import (
    generate_masked_patterns,
    mask_volatile_x64_bytes,
    normalize_pattern,
    parse_ida_pattern,
    resolve_relative_from_image,
    scan_ida_pattern,
)
from src.ui import sigcli


class TestSignaturePatternHelpers(unittest.TestCase):
    def test_parse_and_scan_ida_patterns(self):
        values, mask = parse_ida_pattern("48 8B ? ? E8 ?? ?? ?? ??")
        self.assertEqual(values[:2], [0x48, 0x8B])
        self.assertEqual(mask, [True, True, False, False, True, False, False, False, False])
        data = bytes.fromhex("90 48 8B 11 22 E8 01 02 03 04 90")
        self.assertEqual(scan_ida_pattern(data, "48 8B ? ? E8 ? ? ? ?", max_results=10), [1])

    def test_resolve_relative_call(self):
        # E8 05 00 00 00 at RVA 0x100 resolves to 0x10A.
        data = b"\xE8\x05\x00\x00\x00" + b"\x90" * 16
        self.assertEqual(
            resolve_relative_from_image(data, 0x100, 0, 0x180000000, disp_offset=1, instruction_size=5),
            (0x10A, 0x18000010A),
        )

    def test_mask_volatile_bytes_for_generation(self):
        code = bytes.fromhex("48 83 EC 28 E8 11 22 33 44 48 8D 05 AA BB CC DD")
        pattern = normalize_pattern(" ".join(f"{b:02X}" if fixed else "?" for b, fixed in zip(code, mask_volatile_x64_bytes(code))))
        self.assertIn("48 83 EC ?", pattern)
        self.assertIn("E8 ? ? ? ?", pattern)
        self.assertIn("48 8D 05 ? ? ? ?", pattern)

    def test_generate_candidates_scores_unique_window(self):
        data = bytes.fromhex("90 90 48 83 EC 28 E8 01 00 00 00 48 8D 05 02 00 00 00 C3 90")
        candidates = generate_masked_patterns("client.dll", 0x180000000, data, 2, 2, lengths=(16,))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].hit_count, 1)
        self.assertEqual(candidates[0].score, "strong")


class TestSignaturePackParser(unittest.TestCase):
    def test_parse_module_comments_patterns_and_exports(self):
        pack = '''
// client.dll
#define CREATEMOVE_PATTERN "48 8B C4 4C 89 40 ?"
// tier0.dll
#define LOADKV3_PROC_ADDRESS "?LoadKV3@@YA_NPEAVKeyValues3@@Z"
'''
        entries = parse_signature_pack(pack)
        self.assertEqual(entries[0].name, "CREATEMOVE")
        self.assertEqual(entries[0].module, "client.dll")
        self.assertEqual(entries[0].kind, "pattern")
        self.assertEqual(entries[1].name, "LOADKV3")
        self.assertEqual(entries[1].module, "tier0.dll")
        self.assertEqual(entries[1].kind, "export")
        self.assertEqual(entries[1].symbol, "?LoadKV3@@YA_NPEAVKeyValues3@@Z")

    def test_extended_catalog_contains_user_style_entries(self):
        entries = {(entry.module.lower(), entry.name): entry for entry in extended_entries()}
        self.assertIn(("gameoverlayrenderer64.dll", "PRESENT"), entries)
        self.assertIn(("client.dll", "CREATEMOVE"), entries)
        self.assertIn(("tier0.dll", "LOADKV3"), entries)
        self.assertEqual(entries[("tier0.dll", "LOADKV3")].kind, "export")

    def test_catalog_adapters_include_existing_tables(self):
        entries = get_catalog_entries("tables", include_researched=False)
        names = {entry.name for entry in entries}
        self.assertIn("dwEntityList", names)
        self.assertIn("fnCreateMove", names)
        self.assertIn("CreateMove", names)


class TestSigCliPromote(unittest.TestCase):
    def test_promote_apply_writes_researched_signature_table(self):
        proposal = {
            "candidates": [
                {
                    "name": "UnitTestSig",
                    "module": "client.dll",
                    "pattern": "48 8B ? ?",
                    "rva": "0x1234",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "proposal.json")
            target_path = os.path.join(temp_dir, "researched_signatures.json")
            with open(input_path, "w", encoding="utf-8") as handle:
                json.dump(proposal, handle)

            rc = sigcli.main(["promote", "--input", input_path, "--target", target_path, "--apply"])
            self.assertEqual(rc, 0)
            with open(target_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["signatures"][0]["name"], "UnitTestSig")


if __name__ == "__main__":
    unittest.main()
