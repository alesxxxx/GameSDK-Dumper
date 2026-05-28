
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

@dataclass
class TypeDesc:
    kind: str
    display_name: str = ""
    full_name: str = ""
    package: str = ""
    size: int = 0
    align: int = 0
    is_const: bool = False
    is_ref: bool = False
    pointee: Optional["TypeDesc"] = None
    inner: Optional["TypeDesc"] = None
    key: Optional["TypeDesc"] = None
    value: Optional["TypeDesc"] = None
    enum_underlying: Optional["TypeDesc"] = None
    signature_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BoolMeta:
    is_native: bool
    field_mask: int = 0xFF
    byte_offset: int = 0
    bit_index: int = -1

@dataclass
class StructLayoutMeta:
    min_alignment: int = 1
    aligned_size: int = 0
    unaligned_size: int = 0
    highest_member_alignment: int = 1
    last_member_end: int = 0
    super_size: int = 0
    reuses_super_tail_padding: bool = False

@dataclass
class MemberInfo:
    name: str
    offset: int
    size: int
    type_name: str
    array_dim: int = 1
    is_static: bool = False
    flags: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    type_desc: Optional[TypeDesc] = None
    bool_meta: Optional[BoolMeta] = None
    property_ptr: int = 0
    storage_offset: int = -1

@dataclass
class FunctionParamInfo:
    name: str
    offset: int
    size: int
    type_name: str
    flags: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    type_desc: Optional[TypeDesc] = None
    bool_meta: Optional[BoolMeta] = None
    property_ptr: int = 0
    storage_offset: int = -1

@dataclass
class FunctionInfo:
    name: str
    address: int
    rva: int = 0
    flags: int = 0
    exec_func: int = 0
    params: List[FunctionParamInfo] = field(default_factory=list)
    return_param: Optional[FunctionParamInfo] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class StructInfo:
    name: str
    full_name: str
    address: int
    size: int
    super_name: str = ""
    is_class: bool = False
    package: str = ""
    members: List[MemberInfo] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    super_chain: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    super_full_name: str = ""
    layout: Optional[StructLayoutMeta] = None

@dataclass
class EnumInfo:
    name: str
    full_name: str
    address: int
    values: List[Tuple[str, int]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SDKDump:
    structs: List[StructInfo] = field(default_factory=list)
    enums: List[EnumInfo] = field(default_factory=list)
    object_count: int = 0
    gnames_ptr: int = 0
    gobjects_ptr: int = 0
    gworld_ptr: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
