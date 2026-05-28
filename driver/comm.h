/*
 * comm.h — Shared memory IPC protocol between wdfsvc64.sys and user-mode
 * client.
 *
 * The driver creates a named section that both the kernel driver and user-mode
 * Python can map.  Communication happens via a single 64KB shared page.
 *
 * Protocol:
 *   1. Client writes a MEMORY_COMMAND struct to the shared page.
 *   2. Client sets MagicCode = COMMAND_MAGIC last (this is the "go" signal).
 *   3. The kernel worker sees the magic, executes the command.
 *   4. Results are written into the data area (offset +48 in the page).
 *   5. The kernel sets Status = CMD_STATUS_COMPLETE (or CMD_STATUS_ERROR).
 *   6. Client polls Status until != CMD_STATUS_WAITING.
 *
 * The shared page layout:
 *   [0..47]   MEMORY_COMMAND header (48 bytes)
 *   [48..65535] Data area (65488 bytes) — read results / write payload
 *
 * Anti-detection:
 *   - Section name generated at runtime from boot entropy — no static GUID.
 *   - No IOCTL device objects, no symbolic links.
 *   - No DbgPrint unless NOVA_DEBUG is defined.
 *   - Reads use MmCopyMemory (physical) — not MmMapIoSpace or
 * MmCopyVirtualMemory.
 *   - Writes use MDL-based physical mapping — not MmMapIoSpace.
 *   - No import table references to hooked APIs.
 *   - Magic constants are non-ASCII to avoid string scanning fingerprints.
 */

#pragma once

#include <ntifs.h>

/* ─── Command IDs ─────────────────────────────────────────── */

/*
 * Non-ASCII magic values — BattlEye/EAC scan kernel memory for readable
 * ASCII strings like 'NOVA', 'NVMR', etc.  Using non-printable byte
 * sequences eliminates this fingerprint.
 */
#define COMMAND_MAGIC 0xD3C2B1A0 /* Trigger signal (non-ASCII) */
#define COMMAND_READ 1           /* Physical read: target → shared page */
#define COMMAND_WRITE 2          /* Physical write: shared page → target */
#define COMMAND_GETBASE 3        /* PsGetProcessSectionBaseAddress */
#define COMMAND_FINDCR3 4        /* Read DirectoryTableBase from EPROCESS */
#define COMMAND_SCATTER_READ 5   /* Batch read: multiple (addr, size) pairs */
#define COMMAND_HEALTH_CHECK 6   /* Driver liveness + capability check */
#define COMMAND_READ_TOLERANT                                                  \
  7 /* Tolerant bulk read: zero-fill unreadable pages */

/* ─── Status Codes ────────────────────────────────────────── */

#define CMD_STATUS_WAITING 0  /* Python wrote command, kernel hasn't started */
#define CMD_STATUS_COMPLETE 1 /* Kernel finished successfully */
#define CMD_STATUS_ERROR 2    /* Kernel encountered an error */

/* ─── Health Check Magic ──────────────────────────────────── */

#define HEALTH_CHECK_MAGIC 0xE7F6A5B4 /* Non-ASCII echo value */

/* ─── Shared Memory ───────────────────────────────────────── */

/*
 * Section name is generated at runtime from boot entropy in DriverEntry.
 * The prefix is used by the Python client to discover the section by
 * enumerating \BaseNamedObjects\Global\ and matching the prefix pattern.
 *
 * Format: \BaseNamedObjects\Global\{wdf-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
 *
 * The 'wdf-' prefix mimics Windows Driver Framework section objects.
 * The remaining 32 hex chars are derived from boot-time entropy.
 */
#define COMM_SECTION_PREFIX L"\\BaseNamedObjects\\Global\\{wdf-"
#define COMM_SECTION_NAME_MAXLEN 128 /* Max chars for generated name */
#define COMM_PAGE_SIZE 65536 /* 64 KB — 16x throughput per IPC command */
#define COMM_HEADER_SIZE 48
#define COMM_DATA_MAXSIZE (COMM_PAGE_SIZE - COMM_HEADER_SIZE) /* 65488 bytes   \
                                                               */

/* ─── Command Struct ──────────────────────────────────────── */

#pragma pack(push, 8)
typedef struct _MEMORY_COMMAND {
  ULONG MagicCode;         /* 0x00: Must be COMMAND_MAGIC to trigger */
  ULONG Instruction;       /* 0x04: COMMAND_READ, COMMAND_WRITE, etc. */
  ULONG ProcessId;         /* 0x08: Target PID */
  ULONG _Pad0;             /* 0x0C: Alignment padding */
  ULONGLONG TargetAddress; /* 0x10: Virtual address in target process */
  ULONGLONG BufferAddress; /* 0x18: Unused (data goes into page +48) */
  SIZE_T Size;             /* 0x20: Byte count to read/write */
  ULONG Status;            /* 0x28: CMD_STATUS_* */
  ULONG _Pad1;             /* 0x2C: Alignment padding */
                           /* Total: 48 bytes (0x30) */
} MEMORY_COMMAND, *PMEMORY_COMMAND;
#pragma pack(pop)

/* Verify struct size at compile time */
C_ASSERT(sizeof(MEMORY_COMMAND) == COMM_HEADER_SIZE);

/* ─── Scatter Read Entry ──────────────────────────────────── */

/*
 * For COMMAND_SCATTER_READ, the data area contains an array of
 * SCATTER_ENTRY structs on input. On output, the kernel replaces
 * the data area with concatenated read results.
 *
 * Input format:
 *   MEMORY_COMMAND.TargetAddress = number of entries
 *   MEMORY_COMMAND.Size = total expected response size
 *   Data area: SCATTER_ENTRY[n]
 *
 * Output format:
 *   Data area: concatenated bytes (entry0_data | entry1_data | ...)
 */

#pragma pack(push, 1)
typedef struct _SCATTER_ENTRY {
  ULONGLONG Address; /* Virtual address to read */
  ULONG Size;        /* Bytes to read from this address */
} SCATTER_ENTRY, *PSCATTER_ENTRY;
#pragma pack(pop)

#define SCATTER_ENTRY_SIZE sizeof(SCATTER_ENTRY) /* 12 bytes */
#define SCATTER_MAX_ENTRIES (COMM_DATA_MAXSIZE / SCATTER_ENTRY_SIZE)

/* ─── Debug Logging ───────────────────────────────────────── */

#ifdef NOVA_DEBUG
#define NOVA_LOG(fmt, ...)                                                     \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[wdf] " fmt "\n",        \
             ##__VA_ARGS__)
#else
#define NOVA_LOG(fmt, ...) ((void)0)
#endif
