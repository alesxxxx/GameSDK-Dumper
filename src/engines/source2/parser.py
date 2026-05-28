import logging
from typing import List

from src.core.memory import read_uint64, read_uint32, read_uint16, read_bytes, read_string

logger = logging.getLogger(__name__)


class CUtlTSHashParser:
    """
    Iterates a CUtlTsHash<T, 256> from CS2 memory.

    Reference layout (from a2x/cs2-dumper):
      UtlTsHash<D, C=256, K=u64>:
        0x0000: entry_mem   (UtlMemoryPool, 0x60 bytes)
        0x0060: buckets     ([UtlTsHashBucket; 256])  -- each bucket is 0x18 bytes

      UtlMemoryPool:
        0x0000: block_size          (i32)
        0x0004: blocks_per_blob     (i32)
        0x0008: grow_mode           (u32)
        0x000C: blocks_allocated    (i32)
        0x0010: peak_allocated      (i32)
        0x0020: free_blocks         (TsListBase -> TsListHead -> next ptr)
        0x0048: blob_head           (ptr to UtlMemoryPoolBlob)

      UtlTsHashBucket<D, K>:
        0x0000: add_lock            (usize, 8 bytes on x64)
        0x0008: first               (ptr to UtlTsHashFixedData)
        0x0010: first_uncommitted   (ptr to UtlTsHashFixedData)

      UtlTsHashFixedData<D, K=u64>:
        0x0000: ui_key              (K = u64, 8 bytes)
        0x0008: next                (ptr to next UtlTsHashFixedData)
        0x0010: data                (ptr to D)

      UtlTsHashAllocatedBlob<D>:
        0x0000: next                (ptr to next blob)
        0x0008: pad
        0x0010: data                (ptr to D)
    """

    ENTRY_MEM_OFFSET = 0x0000
    BUCKETS_OFFSET = 0x0060
    BUCKET_SIZE = 0x18  # sizeof(UtlTsHashBucket) on x64
    BUCKET_COUNT = 256

    # UtlMemoryPool field offsets
    POOL_BLOCKS_ALLOCATED = 0x000C
    POOL_PEAK_ALLOCATED = 0x0010
    POOL_FREE_BLOCKS = 0x0020  # TsListBase -> TsListHead -> next (ptr at +0x0)
    POOL_BLOB_HEAD = 0x0048

    # UtlTsHashBucket field offsets (relative to bucket start)
    BUCKET_FIRST = 0x0008
    BUCKET_FIRST_UNCOMMITTED = 0x0010

    # UtlTsHashFixedData field offsets
    FIXED_KEY = 0x0000
    FIXED_NEXT = 0x0008
    FIXED_DATA = 0x0010

    # UtlTsHashAllocatedBlob offsets
    BLOB_NEXT = 0x0000
    BLOB_DATA = 0x0010

    def __init__(self, handle: int, address: int):
        self.handle = handle
        self.address = address

        pool_addr = address + self.ENTRY_MEM_OFFSET
        self.blocks_allocated = read_uint32(handle, pool_addr + self.POOL_BLOCKS_ALLOCATED)
        self.peak_allocated = read_uint32(handle, pool_addr + self.POOL_PEAK_ALLOCATED)

    def iter_elements(self) -> List[int]:
        """Return all data pointers from both bucket lists and free-block blobs."""
        allocated = self._allocated_elements()
        unallocated = self._unallocated_elements()

        # Combine and deduplicate
        seen = set()
        result = []
        for ptr in allocated + unallocated:
            if ptr and ptr not in seen:
                seen.add(ptr)
                result.append(ptr)

        return result

    def _allocated_elements(self) -> List[int]:
        """Walk the 256 bucket linked lists (first_uncommitted chains)."""
        elements = []
        limit = max(self.blocks_allocated, 8192)  # safety cap
        seen_nodes = set()

        buckets_base = self.address + self.BUCKETS_OFFSET

        for b in range(self.BUCKET_COUNT):
            bucket_addr = buckets_base + (b * self.BUCKET_SIZE)
            node_ptr = read_uint64(self.handle, bucket_addr + self.BUCKET_FIRST_UNCOMMITTED)

            while node_ptr:
                if node_ptr in seen_nodes:
                    break
                seen_nodes.add(node_ptr)

                # Read UtlTsHashFixedData
                data_ptr = read_uint64(self.handle, node_ptr + self.FIXED_DATA)
                if data_ptr:
                    elements.append(data_ptr)

                if len(elements) >= limit:
                    return elements

                node_ptr = read_uint64(self.handle, node_ptr + self.FIXED_NEXT)

        return elements

    def _unallocated_elements(self) -> List[int]:
        """Walk the free-blocks blob chain from from the memory pool."""
        elements = []
        limit = max(self.peak_allocated, 8192)  # safety cap
        seen_nodes = set()

        pool_addr = self.address + self.ENTRY_MEM_OFFSET
        # free_blocks is TsListBase { head: TsListHead { next: ptr } }
        # TsListHead.next is at offset 0x0 within TsListHead
        # TsListBase starts at POOL_FREE_BLOCKS
        blob_ptr = read_uint64(self.handle, pool_addr + self.POOL_FREE_BLOCKS)

        while blob_ptr:
            if blob_ptr in seen_nodes:
                break
            seen_nodes.add(blob_ptr)

            data_ptr = read_uint64(self.handle, blob_ptr + self.BLOB_DATA)
            if data_ptr:
                elements.append(data_ptr)

            if len(elements) >= limit:
                break

            blob_ptr = read_uint64(self.handle, blob_ptr + self.BLOB_NEXT)

        return elements


def get_type_scope_classes(handle: int, type_scope_ptr: int) -> List[int]:
    """Extract SchemaClassInfoData pointers from CSchemaSystemTypeScope.

    class_bindings (UtlTsHash<SchemaClassBinding>) is at +0x560 in the TypeScope.
    """
    hash_parser = CUtlTSHashParser(handle, type_scope_ptr + 0x560)
    return hash_parser.iter_elements()


def get_type_scope_enums(handle: int, type_scope_ptr: int) -> List[int]:
    """Extract SchemaEnumInfoData pointers from CSchemaSystemTypeScope.

    enum_bindings (UtlTsHash<SchemaEnumBinding>) is at +0x1DD0 in the TypeScope.
    """
    hash_parser = CUtlTSHashParser(handle, type_scope_ptr + 0x1DD0)
    return hash_parser.iter_elements()
