import json
import os
import struct
import tempfile
import unittest
from unittest import mock

from src.core.models import EnumInfo, MemberInfo, SDKDump, StructInfo
from src.engines.source2 import buttons, dumper, interfaces
from src.engines.source2.buttons import CS2ButtonResult
from src.engines.source2.interfaces import CS2InterfaceModuleResult, CS2InterfaceResult
from src.output.source2_runtime_writer import (
    write_cs2_buttons_header,
    write_cs2_buttons_json,
    write_cs2_info_json,
    write_cs2_interfaces_header,
    write_cs2_interfaces_json,
)
from src.output.source2_writer import write_source2_header


class TestSource2ReferenceScanners(unittest.TestCase):
    def test_button_linked_list_extracts_state_rvas(self):
        module_base = 0x10000000
        first = module_base + 0x2000
        second = module_base + 0x2200
        ptrs = {
            first + 0x08: 0x5000,
            first + 0x88: second,
            second + 0x08: 0x5010,
            second + 0x88: 0,
        }
        strings = {0x5000: "jump", 0x5010: "attack"}

        with mock.patch.object(buttons, "read_uint64", side_effect=lambda _h, a: ptrs.get(a, 0)), \
             mock.patch.object(buttons, "read_string", side_effect=lambda _h, a, max_len=32: strings.get(a, "")):
            results = buttons.read_buttons_from_list(1, module_base, first)

        by_name = {item.name: item for item in results}
        self.assertEqual(by_name["jump"].rva, 0x2030)
        self.assertEqual(by_name["attack"].rva, 0x2230)

    def test_interface_registry_extracts_instance_rvas(self):
        module_base = 0x70000000
        reg = 0x4000
        create_fn = 0x5000
        instance = module_base + 0x1234
        ptrs = {
            reg + 0x00: create_fn,
            reg + 0x08: 0x6000,
            reg + 0x10: 0,
        }

        with mock.patch.object(interfaces, "read_uint64", side_effect=lambda _h, a: ptrs.get(a, 0)), \
             mock.patch.object(interfaces, "read_string", side_effect=lambda _h, a, max_len=128: "VClient018" if a == 0x6000 else ""), \
             mock.patch.object(interfaces, "resolve_rip", return_value=instance):
            results = interfaces.read_interfaces_from_list(1, "client.dll", module_base, reg)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "VClient018")
        self.assertEqual(results[0].rva, 0x1234)
        self.assertEqual(results[0].create_fn, create_fn)

    def test_enum_binding_conversion_preserves_metadata(self):
        enum_ptr = 0x1000
        members_ptr = 0x3000
        metadata_ptr = 0x4000
        network_value = 0x5000
        ptrs = {
            enum_ptr + 0x08: 0x2000,
            enum_ptr + 0x10: 0x2008,
            enum_ptr + 0x20: members_ptr,
            enum_ptr + 0x28: metadata_ptr,
            members_ptr + 0x00: 0x2010,
            members_ptr + 0x20: 0x2020,
            metadata_ptr + 0x00: 0x2030,
            metadata_ptr + 0x08: network_value,
            network_value + 0x00: 0x2040,
            network_value + 0x08: 0x2050,
        }
        u16s = {
            enum_ptr + 0x1C: 2,
            enum_ptr + 0x1E: 1,
        }
        strings = {
            0x2000: "EMoveType",
            0x2008: "client",
            0x2010: "MOVETYPE_NONE",
            0x2020: "MOVETYPE_WALK",
            0x2030: "MNetworkVarNames",
            0x2040: "m_MoveType",
            0x2050: "Move Type",
        }

        def fake_bytes(_handle, address, size):
            if size == 1:
                return {
                    enum_ptr + 0x18: b"\x08",
                    enum_ptr + 0x19: b"\x08",
                    enum_ptr + 0x1A: b"\x00",
                }.get(address, b"\x00")
            if size == 8:
                if address == members_ptr + 0x08:
                    return struct.pack("<q", 0)
                if address == members_ptr + 0x28:
                    return struct.pack("<q", 2)
            return b"\x00" * size

        with mock.patch.object(dumper, "read_uint64", side_effect=lambda _h, a: ptrs.get(a, 0)), \
             mock.patch.object(dumper, "read_uint16", side_effect=lambda _h, a: u16s.get(a, 0)), \
             mock.patch.object(dumper, "read_uint32", return_value=0), \
             mock.patch.object(dumper, "read_bytes", side_effect=fake_bytes), \
             mock.patch.object(dumper, "read_string", side_effect=lambda _h, a, max_len=128: strings.get(a, "")):
            enum_info = dumper.read_enum_binding(1, enum_ptr, "client.dll")

        self.assertIsNotNone(enum_info)
        self.assertEqual(enum_info.name, "EMoveType")
        self.assertEqual(enum_info.full_name, "Source2.client.dll.EMoveType")
        self.assertEqual(enum_info.values, [("MOVETYPE_NONE", 0), ("MOVETYPE_WALK", 2)])
        metadata = enum_info.metadata["source2_metadata"][0]
        self.assertEqual(metadata["kind"], "network_var_names")
        self.assertEqual(metadata["var_name"], "m_MoveType")
        self.assertEqual(metadata["type_name"], "MoveType")


class TestSource2ReferenceWriters(unittest.TestCase):
    def test_runtime_writers_emit_buttons_interfaces_and_info(self):
        buttons_results = [
            CS2ButtonResult("jump", "client.dll", 0x2030, 0x10002030),
            CS2ButtonResult("attack", "client.dll", 0x2230, 0x10002230),
        ]
        interfaces_results = [
            CS2InterfaceModuleResult(
                module="client.dll",
                base=0x10000000,
                size=0x100000,
                interfaces=[
                    CS2InterfaceResult("VClient018", "client.dll", 0x1234, 0x10001234, 0x5000)
                ],
            )
        ]
        enum = EnumInfo(
            name="EFixture",
            full_name="Source2.client.dll.EFixture",
            address=0,
            values=[("ValueA", 1)],
            metadata={"source2_module": "client.dll"},
        )
        struct = StructInfo(
            name="C_Fixture",
            full_name="Source2.client.dll.C_Fixture",
            address=0,
            size=0x20,
            is_class=True,
            package="client.dll",
            members=[MemberInfo("m_value", 0x10, 0, "int32")],
            metadata={"source2_module": "client.dll", "source2_metadata": []},
        )
        sdk_dump = SDKDump(structs=[struct], enums=[enum])

        with tempfile.TemporaryDirectory() as temp_dir:
            buttons_h = os.path.join(temp_dir, "cs2_buttons.hpp")
            buttons_j = os.path.join(temp_dir, "cs2_buttons.json")
            interfaces_h = os.path.join(temp_dir, "cs2_interfaces.hpp")
            interfaces_j = os.path.join(temp_dir, "cs2_interfaces.json")
            schemas_h = os.path.join(temp_dir, "cs2_schemas.hpp")
            info_j = os.path.join(temp_dir, "cs2_info.json")

            write_cs2_buttons_header(buttons_h, buttons_results, "cs2.exe")
            write_cs2_buttons_json(buttons_j, buttons_results, "cs2.exe")
            write_cs2_interfaces_header(interfaces_h, interfaces_results, "cs2.exe")
            write_cs2_interfaces_json(interfaces_j, interfaces_results, "cs2.exe")
            write_source2_header(schemas_h, sdk_dump, "cs2.exe")
            write_cs2_info_json(
                info_j,
                process_name="cs2.exe",
                sdk_dump=sdk_dump,
                globals_results=[],
                buttons_results=buttons_results,
                interfaces_results=interfaces_results,
            )

            with open(buttons_h, "r", encoding="utf-8") as handle:
                self.assertIn("inline constexpr std::ptrdiff_t jump = 0x2030;", handle.read())
            with open(interfaces_h, "r", encoding="utf-8") as handle:
                self.assertIn("inline constexpr std::ptrdiff_t VClient018 = 0x1234;", handle.read())
            with open(schemas_h, "r", encoding="utf-8") as handle:
                schema_text = handle.read()
            self.assertIn("enum class EFixture", schema_text)
            self.assertIn("namespace C_Fixture", schema_text)
            with open(buttons_j, "r", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["buttons"]["client.dll"]["jump"]["rva_int"], 0x2030)
            with open(interfaces_j, "r", encoding="utf-8") as handle:
                self.assertEqual(
                    json.load(handle)["modules"]["client.dll"]["interfaces"]["VClient018"]["rva_int"],
                    0x1234,
                )
            with open(info_j, "r", encoding="utf-8") as handle:
                info = json.load(handle)
            self.assertEqual(info["stats"]["schema_enums"], 1)
            self.assertEqual(info["stats"]["buttons_resolved"], 2)
            self.assertEqual(info["stats"]["interfaces_resolved"], 1)

    def test_build_14156_fixture_covers_expected_button_names_and_enums(self):
        fixture_buttons = [
            "attack",
            "attack2",
            "back",
            "duck",
            "forward",
            "jump",
            "left",
            "reload",
            "right",
            "showscores",
            "use",
            "zoom",
        ]
        button_results = [
            CS2ButtonResult(name, "client.dll", 0x1000 + index * 0x10, 0x50000000 + index)
            for index, name in enumerate(fixture_buttons)
        ]
        sdk_dump = SDKDump(
            enums=[
                EnumInfo(
                    name="EMoveType",
                    full_name="Source2.client.dll.EMoveType",
                    address=0,
                    values=[("MOVETYPE_WALK", 2)],
                )
            ]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            info_path = os.path.join(temp_dir, "cs2_info.json")
            write_cs2_info_json(
                info_path,
                process_name="cs2.exe",
                sdk_dump=sdk_dump,
                globals_results=[],
                buttons_results=button_results,
                interfaces_results=[
                    CS2InterfaceModuleResult(
                        module="client.dll",
                        base=0x10000000,
                        size=0x100000,
                        interfaces=[CS2InterfaceResult("VClient018", "client.dll", 0x1234, 0x10001234)],
                    )
                ],
                build_number=14156,
            )
            with open(info_path, "r", encoding="utf-8") as handle:
                info = json.load(handle)

        self.assertEqual(info["build_number"], 14156)
        self.assertFalse(info["health"]["missing_expected_buttons"])
        self.assertGreater(info["stats"]["schema_enums"], 0)


if __name__ == "__main__":
    unittest.main()
