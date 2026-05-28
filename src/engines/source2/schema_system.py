from typing import List, Optional

class SchemaType:
    def __init__(self):
        self.name: str = ""
        self.type_category: int = 0
        self.struct_name: str = ""

class SchemaClassFieldData_t:
    def __init__(self):
        self.name: str = ""
        self.type_name: str = ""
        self.offset: int = 0
        self.size: int = 0

class SchemaClassInfoData_t:
    def __init__(self):
        self.name: str = ""
        self.module_name: str = ""
        self.size: int = 0
        self.align: int = 0
        self.fields: List[SchemaClassFieldData_t] = []
        self.parent: Optional['SchemaClassInfoData_t'] = None

class SchemaSystemTypeScope:
    def __init__(self):
        self.classes: List[SchemaClassInfoData_t] = []
