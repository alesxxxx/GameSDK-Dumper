/*
 * driver.c — Kernel driver (wdfsvc64.sys).
 *
 * Stealth shared-memory IPC for reading/writing process memory from kernel
 * mode, designed to coexist with kernel-level anti-cheats (EAC, BE, ACE).
 *
 * Flow:
 *   1. DriverEntry creates a GUID-named shared section.
 *   2. A kernel worker polls the shared page for commands (magic trigger).
 *   3. Commands read/write target process memory via CR3 physical translation.
 *   4. Status set to COMPLETE; worker resumes polling.
 *
 * Anti-detection:
 *   - No device objects, no symbolic links, no IOCTLs.
 *   - Section name is a GUID — blends with COM/WinRT section objects.
 *   - All reads use MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) — NOT MmMapIoSpace
 *     (hooked by EAC since ~2023) and NOT MmCopyVirtualMemory (hooked by all).
 *   - Writes use MmMapIoSpace (rare operation, low detection surface).
 *   - EPROCESS cached to minimise PsLookupProcessByProcessId calls.
 *   - DTB offset auto-probed and validated via MZ signature check.
 *   - Pool allocations use generic Windows-looking tags.
 *   - Worker thread sleeps 100 µs between polls (no spin-loop fingerprint).
 *   - No debug output unless compiled with NOVA_DEBUG.
 */

#include "comm.h"
#include <ntddk.h>
#include <ntstrsafe.h>

/* ─── CRT Stripping ───────────────────────────────────────── */
/*
 * EAC scans unbacked kernel memory for MSVC CRT patterns:
 * statically linked memset/memcpy, _cpu_features_init, etc.
 * We provide our own implementations using compiler intrinsics
 * (__stosb / __movsb) to avoid linking the CRT versions.
 *
 * #pragma function() forces the compiler to use our function
 * definitions instead of generating intrinsic calls.
 */
#pragma function(memset)
void *memset(void *dest, int val, size_t count) {
  __stosb((unsigned char *)dest, (unsigned char)val, count);
  return dest;
}

#pragma function(memcpy)
void *memcpy(void *dest, const void *src, size_t count) {
  __movsb((unsigned char *)dest, (const unsigned char *)src, count);
  return dest;
}

/* MmCopyMemory flag — read from physical address */
#ifndef MM_COPY_MEMORY_PHYSICAL
#define MM_COPY_MEMORY_PHYSICAL 0x2
#endif

/* ─── Forward declarations ────────────────────────────────── */

static NTSTATUS CreateAndMapSharedSection(void);
static NTSTATUS HandleRead(PMEMORY_COMMAND cmd, PVOID dataArea);
static NTSTATUS HandleReadTolerant(PMEMORY_COMMAND cmd, PVOID dataArea);
static NTSTATUS HandleWrite(PMEMORY_COMMAND cmd, PVOID dataArea);
static NTSTATUS HandleGetBase(PMEMORY_COMMAND cmd, PVOID dataArea);
static NTSTATUS HandleFindCr3(PMEMORY_COMMAND cmd, PVOID dataArea);
static NTSTATUS HandleScatterRead(PMEMORY_COMMAND cmd, PVOID dataArea);
static NTSTATUS HandleHealthCheck(PMEMORY_COMMAND cmd, PVOID dataArea);
static PEPROCESS LookupProcess(ULONG pid);
static NTSTATUS ReadPhysicalMemory(ULONGLONG cr3, ULONGLONG virtualAddr,
                                   PVOID buffer, SIZE_T size,
                                   PSIZE_T bytesRead);
static NTSTATUS ReadPhysicalMemoryTolerant(ULONGLONG cr3, ULONGLONG virtualAddr,
                                           PVOID buffer, SIZE_T size,
                                           PSIZE_T bytesRead);
static ULONGLONG VirtToPhys(ULONGLONG cr3, ULONGLONG virtualAddr);
static ULONGLONG VirtToPhysCached(ULONGLONG cr3, ULONGLONG virtualAddr,
                                  PVOID cacheContext, PVOID batchMetrics);
static NTSTATUS ReadPhysicalMemoryCached(ULONGLONG cr3, ULONGLONG virtualAddr,
                                         PVOID buffer, SIZE_T size,
                                         PSIZE_T bytesRead, PVOID cacheContext,
                                         PVOID batchMetrics);

/* ─── Globals ─────────────────────────────────────────────── */

static HANDLE g_SectionHandle = NULL;
static PVOID volatile g_SharedPage = NULL;
static BOOLEAN g_Running = TRUE;
static PUCHAR g_IpcScratch = NULL;

static KTIMER g_PollTimer;
static KDPC g_PollDpc;
static WORK_QUEUE_ITEM g_PollWorkItem;
static KEVENT g_UnloadEvent;

/* Per-boot randomized pool tag — derived from boot entropy in DriverEntry.
 * Replaces the static 'nfMF' tag to prevent pool-tag scanning fingerprints.
 * Initialized before any allocations occur. */
static ULONG g_PoolTag =
    'nfMF'; /* Default fallback, overwritten in DriverEntry */

/* Runtime-generated section name (filled in DriverEntry from boot entropy) */
static WCHAR g_SectionName[COMM_SECTION_NAME_MAXLEN] = {0};

/* Cached EPROCESS reference for the current target PID.
 * Avoids calling PsLookupProcessByProcessId on every single command,
 * which ACs monitor for unusual patterns.
 */
static PEPROCESS g_CachedProcess = NULL;
static ULONG g_CachedPid = 0;
static volatile ULONG g_ScatterBatchCount = 0;
static volatile ULONG g_ScatterMergedReads = 0;
static volatile ULONG g_ScatterTranslationHits = 0;
static volatile ULONG g_ScatterTranslationLookups = 0;

typedef struct _TRANSLATION_CACHE_ENTRY {
  ULONGLONG VirtualPage;
  ULONGLONG PhysicalPage;
  BOOLEAN Valid;
} TRANSLATION_CACHE_ENTRY, *PTRANSLATION_CACHE_ENTRY;

typedef struct _READ_BATCH_METRICS {
  ULONG TranslationLookups;
  ULONG TranslationHits;
  ULONG MergedReads;
} READ_BATCH_METRICS, *PREAD_BATCH_METRICS;

/* ─── Kernel exports ──────────────────────────────────────── */

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

/* ─── DirectoryTableBase offset in EPROCESS ───────────────── */
/*
 * This offset varies by Windows build. We try multiple known offsets
 * and validate by reading a known page to confirm we got the right one.
 *
 * Known offsets:
 *   Win10 1507-1703: 0x28
 *   Win10 1709+:     0x28
 *   Win11 21H2+:     0x28
 *   Win Server 2019: 0x28
 *
 * If your build is different, the driver auto-probes offsets 0x18-0x30.
 */
static ULONG g_DtbOffset = 0x28;
static BOOLEAN g_DtbValidated = FALSE;

/* ─── Health check magic — defined in comm.h as HEALTH_CHECK_MAGIC ── */
/* Non-ASCII: 0xE7F6A5B4 — no readable string fingerprint in memory */

/* ─── Physical Memory Translation ─────────────────────────── */
/*
 * Physical memory reads use MmCopyMemory with MM_COPY_MEMORY_PHYSICAL.
 *
 * Why NOT MmMapIoSpace:
 *   - EAC hooks MmMapIoSpace since ~2023 and flags any call that maps
 *     physical RAM addresses (as opposed to actual MMIO device registers).
 *   - MmMapIoSpace creates PTEs and MDLs — visible side-effects.
 *
 * Why NOT MmCopyVirtualMemory:
 *   - Inline-hooked by EAC, BattlEye, and ACE. Instant detection.
 *
 * MmCopyMemory(MM_COPY_MEMORY_PHYSICAL):
 *   - Documented API, available since Windows 8.1.
 *   - Copies directly into a caller-supplied buffer — no mapping, no MDL.
 *   - Used by crash dump and hibernate code — legitimate call pattern.
 *   - Not commonly hooked by current-gen anti-cheats.
 */

static ULONGLONG ReadPhysQword(ULONGLONG physAddr) {
  MM_COPY_ADDRESS src;
  src.PhysicalAddress.QuadPart = (LONGLONG)physAddr;

  ULONGLONG value = 0;
  SIZE_T bytesRead = 0;
  NTSTATUS status = MmCopyMemory(&value, src, sizeof(ULONGLONG),
                                 MM_COPY_MEMORY_PHYSICAL, &bytesRead);

  if (!NT_SUCCESS(status) || bytesRead != sizeof(ULONGLONG))
    return 0;
  return value;
}

static ULONGLONG VirtToPhys(ULONGLONG cr3, ULONGLONG virtualAddr) {
  /*
   * 4-level x86-64 page table walk:
   *   PML4E → PDPTE → PDE → PTE → Physical page
   *
   * Each level indexes 9 bits of the virtual address.
   * The physical address of each table entry is:
   *   (table_base & ~0xFFF) | (index * 8)
   */
  ULONGLONG pml4_index = (virtualAddr >> 39) & 0x1FF;
  ULONGLONG pdpt_index = (virtualAddr >> 30) & 0x1FF;
  ULONGLONG pd_index = (virtualAddr >> 21) & 0x1FF;
  ULONGLONG pt_index = (virtualAddr >> 12) & 0x1FF;
  ULONGLONG page_offset = virtualAddr & 0xFFF;

  /* PML4 → PDPT */
  ULONGLONG pml4e = ReadPhysQword((cr3 & ~0xFFFULL) | (pml4_index * 8));
  if (!(pml4e & 1))
    return 0; /* Not present */

  /* PDPT → PD */
  ULONGLONG pdpte =
      ReadPhysQword((pml4e & 0x000FFFFFFFFFF000ULL) | (pdpt_index * 8));
  if (!(pdpte & 1))
    return 0;

  /* 1GB huge page? */
  if (pdpte & 0x80)
    return (pdpte & 0x000FFFFFC0000000ULL) | (virtualAddr & 0x3FFFFFFF);

  /* PD → PT */
  ULONGLONG pde =
      ReadPhysQword((pdpte & 0x000FFFFFFFFFF000ULL) | (pd_index * 8));
  if (!(pde & 1))
    return 0;

  /* 2MB large page? */
  if (pde & 0x80)
    return (pde & 0x000FFFFFFFE00000ULL) | (virtualAddr & 0x1FFFFF);

  /* PT → Physical page */
  ULONGLONG pte = ReadPhysQword((pde & 0x000FFFFFFFFFF000ULL) | (pt_index * 8));
  if (!(pte & 1))
    return 0;

  return (pte & 0x000FFFFFFFFFF000ULL) | page_offset;
}

static ULONGLONG VirtToPhysCached(ULONGLONG cr3, ULONGLONG virtualAddr,
                                  PVOID cacheContext, PVOID batchMetrics) {
  PTRANSLATION_CACHE_ENTRY cache = (PTRANSLATION_CACHE_ENTRY)cacheContext;
  PREAD_BATCH_METRICS metrics = (PREAD_BATCH_METRICS)batchMetrics;
  ULONGLONG virtualPage = virtualAddr & ~0xFFFULL;
  ULONGLONG pageOffset = virtualAddr & 0xFFFULL;

  if (cache && cache->Valid && cache->VirtualPage == virtualPage) {
    if (metrics)
      metrics->TranslationHits += 1;
    return cache->PhysicalPage | pageOffset;
  }

  if (metrics)
    metrics->TranslationLookups += 1;
  ULONGLONG physAddr = VirtToPhys(cr3, virtualAddr);
  if (physAddr && cache) {
    cache->VirtualPage = virtualPage;
    cache->PhysicalPage = physAddr & ~0xFFFULL;
    cache->Valid = TRUE;
  }
  return physAddr;
}

static NTSTATUS ReadPhysicalMemoryCached(ULONGLONG cr3, ULONGLONG virtualAddr,
                                         PVOID buffer, SIZE_T size,
                                         PSIZE_T bytesRead, PVOID cacheContext,
                                         PVOID batchMetrics) {
  if (!cr3 || !buffer || size == 0) {
    if (bytesRead)
      *bytesRead = 0;
    return STATUS_INVALID_PARAMETER;
  }

  SIZE_T totalRead = 0;
  PUCHAR outBuf = (PUCHAR)buffer;

  while (totalRead < size) {
    ULONGLONG currentVa = virtualAddr + totalRead;
    ULONGLONG physAddr =
        VirtToPhysCached(cr3, currentVa, cacheContext, batchMetrics);
    if (!physAddr)
      break;

    SIZE_T pageRemaining = 0x1000 - (physAddr & 0xFFF);
    SIZE_T chunkSize = min(pageRemaining, size - totalRead);

    MM_COPY_ADDRESS src;
    src.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
    SIZE_T chunkRead = 0;
    NTSTATUS status = MmCopyMemory(outBuf + totalRead, src, chunkSize,
                                   MM_COPY_MEMORY_PHYSICAL, &chunkRead);

    if (!NT_SUCCESS(status))
      break;

    totalRead += chunkRead;
    if (chunkRead < chunkSize)
      break;
  }

  if (bytesRead)
    *bytesRead = totalRead;
  return (totalRead > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static NTSTATUS ReadPhysicalMemory(ULONGLONG cr3, ULONGLONG virtualAddr,
                                   PVOID buffer, SIZE_T size,
                                   PSIZE_T bytesRead) {
  return ReadPhysicalMemoryCached(cr3, virtualAddr, buffer, size, bytesRead,
                                  NULL, NULL);
}

static NTSTATUS ReadPhysicalMemoryTolerant(ULONGLONG cr3, ULONGLONG virtualAddr,
                                           PVOID buffer, SIZE_T size,
                                           PSIZE_T bytesRead) {
  if (!cr3 || !buffer || size == 0) {
    if (bytesRead)
      *bytesRead = 0;
    return STATUS_INVALID_PARAMETER;
  }

  SIZE_T totalFilled = 0;
  SIZE_T totalReadable = 0;
  PUCHAR outBuf = (PUCHAR)buffer;

  while (totalFilled < size) {
    ULONGLONG currentVa = virtualAddr + totalFilled;
    SIZE_T pageOffset = (SIZE_T)(currentVa & 0xFFFULL);
    SIZE_T chunkSize = min(0x1000 - pageOffset, size - totalFilled);
    ULONGLONG physAddr = VirtToPhys(cr3, currentVa);

    if (!physAddr) {
      RtlZeroMemory(outBuf + totalFilled, chunkSize);
      totalFilled += chunkSize;
      continue;
    }

    MM_COPY_ADDRESS src;
    src.PhysicalAddress.QuadPart = (LONGLONG)physAddr;

    SIZE_T chunkRead = 0;
    NTSTATUS status = MmCopyMemory(outBuf + totalFilled, src, chunkSize,
                                   MM_COPY_MEMORY_PHYSICAL, &chunkRead);

    if (!NT_SUCCESS(status) || chunkRead == 0) {
      RtlZeroMemory(outBuf + totalFilled, chunkSize);
      totalFilled += chunkSize;
      continue;
    }

    if (chunkRead < chunkSize) {
      RtlZeroMemory(outBuf + totalFilled + chunkRead, chunkSize - chunkRead);
    }

    totalReadable += chunkRead;
    totalFilled += chunkSize;
  }

  if (bytesRead)
    *bytesRead = totalReadable;
  return STATUS_SUCCESS;
}

static NTSTATUS WritePhysicalMemory(ULONGLONG cr3, ULONGLONG virtualAddr,
                                    PVOID data, SIZE_T size) {
  if (!cr3 || !data || size == 0)
    return STATUS_INVALID_PARAMETER;

  /*
   * MDL-based physical write — replaces MmMapIoSpace.
   *
   * Why NOT MmMapIoSpace:
   *   - EAC hooks MmMapIoSpace since ~2023 and flags any call that maps
   *     physical RAM addresses (as opposed to actual MMIO device registers).
   *   - Its presence in the import table/IAT is a fingerprint even after
   *     PE header wiping.
   *
   * MDL approach:
   *   1. Translate virtual → physical via CR3 page walk
   *   2. Allocate an MDL describing a single physical page
   *   3. Map with MmMapLockedPagesSpecifyCache for writable access
   *   4. Write through the mapping → cleanup
   */
  SIZE_T totalWritten = 0;
  PUCHAR inBuf = (PUCHAR)data;

  while (totalWritten < size) {
    ULONGLONG currentVa = virtualAddr + totalWritten;
    ULONGLONG physAddr = VirtToPhys(cr3, currentVa);
    if (!physAddr)
      break;

    SIZE_T pageRemaining = 0x1000 - (physAddr & 0xFFF);
    SIZE_T chunkSize = min(pageRemaining, size - totalWritten);

    /* Allocate MDL for a kernel virtual address range.
     * We use the driver start address as a dummy VA — the physical
     * pages will be manually specified. */
    PHYSICAL_ADDRESS lowAddr, highAddr, skipBytes;
    lowAddr.QuadPart = (LONGLONG)(physAddr & ~0xFFFULL);
    highAddr.QuadPart = lowAddr.QuadPart + PAGE_SIZE;
    skipBytes.QuadPart = 0;

    PMDL mdl = MmAllocatePagesForMdlEx(lowAddr, highAddr, skipBytes, PAGE_SIZE,
                                       MmNonCached,
                                       MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS);
    if (!mdl)
      break;

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mapped) {
      MmFreePagesFromMdl(mdl);
      ExFreePool(mdl);
      break;
    }

    /* Write at the correct page offset */
    SIZE_T pageOffset = (SIZE_T)(physAddr & 0xFFF);
    RtlCopyMemory((PUCHAR)mapped + pageOffset, inBuf + totalWritten, chunkSize);

    MmUnmapLockedPages(mapped, mdl);
    MmFreePagesFromMdl(mdl);
    ExFreePool(mdl);

    totalWritten += chunkSize;
  }

  return (totalWritten == size) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* ─── DTB Offset Validation ───────────────────────────────── */

static BOOLEAN ValidateDtbOffset(PEPROCESS process, ULONG offset) {
  if (!process)
    return FALSE;

  /*
   * Validate that the offset we're reading from EPROCESS is actually
   * the DirectoryTableBase by checking if we can translate the process's
   * known base address through the CR3 we read.
   */
  PUCHAR processPtr = (PUCHAR)process;
  if (offset > 0x1000)
    return FALSE; /* Sanity check offset */

  /* Verify the memory at the probed offset is valid before reading.
   * A bad offset into EPROCESS causes a direct kernel page fault → BSOD. */
  if (!MmIsAddressValid(processPtr + offset))
    return FALSE;

  ULONGLONG cr3 = *(PULONGLONG)(processPtr + offset);
  if (!cr3 || (cr3 & 0xFFF)) /* CR3 must be page-aligned */
    return FALSE;

  PVOID baseAddr = PsGetProcessSectionBaseAddress(process);
  if (!baseAddr)
    return FALSE;

  /* Try to read the MZ signature at the process base via MmCopyMemory */
  ULONGLONG physAddr = VirtToPhys(cr3, (ULONGLONG)baseAddr);
  if (!physAddr)
    return FALSE;

  MM_COPY_ADDRESS src;
  src.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
  USHORT mzSig = 0;
  SIZE_T bytesRead = 0;
  if (!NT_SUCCESS(MmCopyMemory(&mzSig, src, sizeof(USHORT),
                               MM_COPY_MEMORY_PHYSICAL, &bytesRead)))
    return FALSE;

  return (mzSig == 0x5A4D); /* 'MZ' */
}

static ULONG ProbeDtbOffset(PEPROCESS process) {
  /* Try known offsets, validate each one */
  static const ULONG candidates[] = {0x28, 0x20, 0x18, 0x30};

  for (ULONG i = 0; i < ARRAYSIZE(candidates); i++) {
    if (ValidateDtbOffset(process, candidates[i])) {
      NOVA_LOG("DTB offset validated: 0x%X", candidates[i]);
      return candidates[i];
    }
  }

  NOVA_LOG("ERROR: Could not validate DTB offset — all candidates failed. "
           "Reads will be rejected until a valid DTB is found.");
  return 0;
}

/* ─── Section Creation & Mapping ─────────────────────────── */
/*
 * MmMapViewInSystemSpace maps the section into kernel (system) address
 * space — a VA range above 0xFFFF... that is visible from every process
 * context and is immune to SMAP/KVAS user-page faults.
 *
 * Previous approach used ZwMapViewOfSection(NtCurrentProcess()) from
 * the worker thread, which mapped into USER space of the System process.
 * On Win11 24H2 with SMAP enabled, kernel code reading a user-mode VA
 * triggers #PF → KMODE_EXCEPTION_NOT_HANDLED (0x1E / 0xC0000005).
 *
 * MmMapViewInSystemSpace is process-context-independent, so we can
 * safely call it from DriverEntry (even when running inside a manual mapper's
 * process context).
 */

/* Declare MmSectionObjectType for ObReferenceObjectByHandle */
extern POBJECT_TYPE *MmSectionObjectType;

static NTSTATUS BuildRestrictedSecurityDescriptor(PSECURITY_DESCRIPTOR *outSd,
                                                  PACL *outDacl) {
  /*
   * Build a security descriptor that only allows SYSTEM and the
   * built-in Administrators group (S-1-5-32-544) to access the
   * shared section.  This prevents unprivileged processes from
   * opening the section and injecting rogue commands.
   */
  NTSTATUS status;
  ULONG aclSize;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;

  /* Well-known SIDs */
  UCHAR systemSidBuf[SECURITY_MAX_SID_SIZE];
  UCHAR adminsSidBuf[SECURITY_MAX_SID_SIZE];
  PSID systemSid = (PSID)systemSidBuf;
  PSID adminsSid = (PSID)adminsSidBuf;

  /* SYSTEM: S-1-5-18 */
  {
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    RtlZeroMemory(systemSidBuf, sizeof(systemSidBuf));
    status = RtlInitializeSid(systemSid, &ntAuth, 1);
    if (!NT_SUCCESS(status))
      return status;
    *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
  }
  /* Administrators: S-1-5-32-544 */
  {
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    RtlZeroMemory(adminsSidBuf, sizeof(adminsSidBuf));
    status = RtlInitializeSid(adminsSid, &ntAuth, 2);
    if (!NT_SUCCESS(status))
      return status;
    *RtlSubAuthoritySid(adminsSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(adminsSid, 1) = DOMAIN_ALIAS_RID_ADMINS;
  }

  aclSize = sizeof(ACL) + 2 * FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
            RtlLengthSid(systemSid) + RtlLengthSid(adminsSid);

  dacl = (PACL)ExAllocatePool2(POOL_FLAG_NON_PAGED, aclSize, g_PoolTag);
  if (!dacl)
    return STATUS_INSUFFICIENT_RESOURCES;

  status = RtlCreateAcl(dacl, aclSize, ACL_REVISION);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(dacl, g_PoolTag);
    return status;
  }

  status =
      RtlAddAccessAllowedAce(dacl, ACL_REVISION, SECTION_ALL_ACCESS, systemSid);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(dacl, g_PoolTag);
    return status;
  }

  status =
      RtlAddAccessAllowedAce(dacl, ACL_REVISION, SECTION_ALL_ACCESS, adminsSid);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(dacl, g_PoolTag);
    return status;
  }

  sd = (PSECURITY_DESCRIPTOR)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, sizeof(SECURITY_DESCRIPTOR), g_PoolTag);
  if (!sd) {
    ExFreePoolWithTag(dacl, g_PoolTag);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  status = RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(sd, g_PoolTag);
    ExFreePoolWithTag(dacl, g_PoolTag);
    return status;
  }

  status = RtlSetDaclSecurityDescriptor(sd, TRUE, dacl, FALSE);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(sd, g_PoolTag);
    ExFreePoolWithTag(dacl, g_PoolTag);
    return status;
  }

  *outSd = sd;
  *outDacl = dacl;
  return STATUS_SUCCESS;
}

static NTSTATUS CreateAndMapSharedSection(void) {
  NTSTATUS status;
  UNICODE_STRING sectionName;
  OBJECT_ATTRIBUTES objAttr;
  LARGE_INTEGER maxSize;
  PSECURITY_DESCRIPTOR sd = NULL;
  PACL dacl = NULL;

  NOVA_LOG("CreateAndMapSharedSection: Starting");

  status = BuildRestrictedSecurityDescriptor(&sd, &dacl);
  if (!NT_SUCCESS(status)) {
    NOVA_LOG("WARNING: Failed to build restricted SD (0x%08X), "
             "falling back to default security",
             status);
    sd = NULL;
    dacl = NULL;
  }

  /* Use the runtime-generated section name (filled by DriverEntry entropy) */
  RtlInitUnicodeString(&sectionName, g_SectionName);
  InitializeObjectAttributes(&objAttr, &sectionName,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             sd);

  maxSize.QuadPart = COMM_PAGE_SIZE;

  status = ZwCreateSection(&g_SectionHandle, SECTION_ALL_ACCESS, &objAttr,
                           &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);

  if (sd)
    ExFreePoolWithTag(sd, g_PoolTag);
  if (dacl)
    ExFreePoolWithTag(dacl, g_PoolTag);

  if (!NT_SUCCESS(status)) {
    NOVA_LOG("ZwCreateSection failed: 0x%08X", status);
    return status;
  }

  NOVA_LOG("Section created, handle: %p", g_SectionHandle);

  /* Get the section object pointer from the handle */
  PVOID sectionObj = NULL;
  status = ObReferenceObjectByHandle(
      g_SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE,
      *MmSectionObjectType, KernelMode, &sectionObj, NULL);
  if (!NT_SUCCESS(status)) {
    NOVA_LOG("ObReferenceObjectByHandle failed: 0x%08X", status);
    ZwClose(g_SectionHandle);
    g_SectionHandle = NULL;
    return status;
  }

  /* Map into system (kernel) address space — NOT user space */
  SIZE_T viewSize = COMM_PAGE_SIZE;
  status =
      MmMapViewInSystemSpace(sectionObj, (PVOID *)&g_SharedPage, &viewSize);
  ObDereferenceObject(sectionObj);

  if (!NT_SUCCESS(status)) {
    NOVA_LOG("MmMapViewInSystemSpace failed: 0x%08X", status);
    ZwClose(g_SectionHandle);
    g_SectionHandle = NULL;
    return status;
  }

  RtlZeroMemory((PVOID)g_SharedPage, COMM_PAGE_SIZE);
  NOVA_LOG("Shared page mapped in system space at %p", g_SharedPage);
  return STATUS_SUCCESS;
}

/* ─── Process Lookup (with caching) ───────────────────────── */

static PEPROCESS LookupProcess(ULONG pid) {
  /*
   * Cache the EPROCESS reference to avoid calling PsLookupProcessByProcessId
   * on every single command. Anti-cheats monitor reference count changes
   * and unusual EPROCESS lookup patterns.
   *
   * The cached reference is held (ObReferenceObject'd) until a different
   * PID is requested or the driver unloads.
   */
  if (g_CachedProcess && g_CachedPid == pid) {
    /* Verify the process is still alive */
    if (!PsGetProcessExitStatus(g_CachedProcess)) {
      return g_CachedProcess;
    }
    /* Process exited — release and re-lookup */
    ObDereferenceObject(g_CachedProcess);
    g_CachedProcess = NULL;
    g_CachedPid = 0;
  }

  /* Release old cached process if PID changed */
  if (g_CachedProcess && g_CachedPid != pid) {
    ObDereferenceObject(g_CachedProcess);
    g_CachedProcess = NULL;
    g_CachedPid = 0;
  }

  PEPROCESS process = NULL;
  NTSTATUS status =
      PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);

  if (!NT_SUCCESS(status))
    return NULL;

  /* Cache it — PsLookupProcessByProcessId already incremented the refcount */
  g_CachedProcess = process;
  g_CachedPid = pid;

  /* Validate/probe DTB offset on first lookup, or re-probe if previous attempt
   * failed */
  if (!g_DtbValidated || g_DtbOffset == 0) {
    g_DtbOffset = ProbeDtbOffset(process);
    g_DtbValidated = (g_DtbOffset != 0);
  }

  return process;
}

static ULONGLONG GetProcessCr3(PEPROCESS process) {
  if (!process)
    return 0;
  if (g_DtbOffset == 0)
    return 0; /* DTB probe failed — refuse to dereference */
  return *(PULONGLONG)((PUCHAR)process + g_DtbOffset);
}

static VOID ZeroSharedDataArea(PVOID dataArea, SIZE_T size) {
  if (!dataArea || size == 0)
    return;
  if (size > COMM_DATA_MAXSIZE)
    size = COMM_DATA_MAXSIZE;
  RtlZeroMemory(dataArea, size);
}

static NTSTATUS CopyScratchToShared(PVOID dataArea, SIZE_T size) {
  if (!dataArea || !g_IpcScratch)
    return STATUS_INVALID_ADDRESS;
  if (size > COMM_DATA_MAXSIZE)
    return STATUS_INVALID_BUFFER_SIZE;
  RtlCopyMemory(dataArea, g_IpcScratch, size);
  return STATUS_SUCCESS;
}

/* ─── Command Handlers ────────────────────────────────────── */

/*
 * Diagnostic info packed into dataArea when a read fails (first 64 bytes):
 *   [0..7]   Magic 'DIAG' (0x4449414744494147)
 *   [8..15]  CR3 value used
 *   [16..23] VirtToPhys result for TargetAddress
 *   [24..31] PML4 entry value
 *   [32..39] PDPT entry value
 *   [40..47] PD entry value
 *   [48..55] PT entry value
 *   [56..59] ReadPhysicalMemory NTSTATUS
 *   [60..63] bytesRead from ReadPhysicalMemory
 */
#define READ_DIAG_MAGIC 0x4449414744494147ULL /* 'DIAGDIAG' */

static void PackReadDiagnostics(PVOID dataArea, ULONGLONG cr3,
                                ULONGLONG virtualAddr, NTSTATUS readStatus,
                                SIZE_T bytesRead) {
  PUCHAR out = (PUCHAR)dataArea;
  RtlZeroMemory(out, 64);

  *(PULONGLONG)(out + 0) = READ_DIAG_MAGIC;
  *(PULONGLONG)(out + 8) = cr3;
  *(PULONGLONG)(out + 16) = VirtToPhys(cr3, virtualAddr);

  /* Walk page table levels individually for diagnostics */
  ULONGLONG pml4_index = (virtualAddr >> 39) & 0x1FF;
  ULONGLONG pdpt_index = (virtualAddr >> 30) & 0x1FF;
  ULONGLONG pd_index = (virtualAddr >> 21) & 0x1FF;
  ULONGLONG pt_index = (virtualAddr >> 12) & 0x1FF;

  ULONGLONG pml4e = ReadPhysQword((cr3 & ~0xFFFULL) | (pml4_index * 8));
  *(PULONGLONG)(out + 24) = pml4e;

  if (pml4e & 1) {
    ULONGLONG pdpte =
        ReadPhysQword((pml4e & 0x000FFFFFFFFFF000ULL) | (pdpt_index * 8));
    *(PULONGLONG)(out + 32) = pdpte;
    if ((pdpte & 1) && !(pdpte & 0x80)) {
      ULONGLONG pde =
          ReadPhysQword((pdpte & 0x000FFFFFFFFFF000ULL) | (pd_index * 8));
      *(PULONGLONG)(out + 40) = pde;
      if ((pde & 1) && !(pde & 0x80)) {
        ULONGLONG pte =
            ReadPhysQword((pde & 0x000FFFFFFFFFF000ULL) | (pt_index * 8));
        *(PULONGLONG)(out + 48) = pte;
      }
    }
  }

  *(PULONG)(out + 56) = (ULONG)readStatus;
  *(PULONG)(out + 60) = (ULONG)bytesRead;
}

static NTSTATUS HandleRead(PMEMORY_COMMAND cmd, PVOID dataArea) {
  if (!cmd || !dataArea)
    return STATUS_INVALID_PARAMETER;
  if (!g_IpcScratch)
    return STATUS_DEVICE_NOT_READY;

  /* Validate size — never allow reads larger than the data area */
  if (cmd->Size == 0 || cmd->Size > COMM_DATA_MAXSIZE)
    return STATUS_INVALID_PARAMETER;

  PEPROCESS targetProcess = LookupProcess(cmd->ProcessId);
  if (!targetProcess)
    return STATUS_NOT_FOUND;

  /* Physical memory read via CR3 page table translation.
   * No fallback to MmCopyVirtualMemory — that API is hooked by all
   * major anti-cheats and would cause instant detection. */
  ULONGLONG cr3 = GetProcessCr3(targetProcess);
  if (!cr3)
    return STATUS_UNSUCCESSFUL;

  SIZE_T bytesRead = 0;
  RtlZeroMemory(g_IpcScratch, cmd->Size);
  NTSTATUS status = ReadPhysicalMemory(cr3, cmd->TargetAddress, g_IpcScratch,
                                       cmd->Size, &bytesRead);

  if (NT_SUCCESS(status) && bytesRead == cmd->Size) {
    return CopyScratchToShared(dataArea, cmd->Size);
  }

  /* Pack diagnostic info for first failed read so Python can log it */
  if (cmd->Size <= COMM_DATA_MAXSIZE) {
    PackReadDiagnostics(dataArea, cr3, cmd->TargetAddress, status, bytesRead);
  }
  return STATUS_UNSUCCESSFUL;
}

static NTSTATUS HandleWrite(PMEMORY_COMMAND cmd, PVOID dataArea) {
  if (!cmd || !dataArea)
    return STATUS_INVALID_PARAMETER;
  if (!g_IpcScratch)
    return STATUS_DEVICE_NOT_READY;

  if (cmd->Size == 0 || cmd->Size > COMM_DATA_MAXSIZE)
    return STATUS_INVALID_PARAMETER;

  PEPROCESS targetProcess = LookupProcess(cmd->ProcessId);
  if (!targetProcess)
    return STATUS_NOT_FOUND;

  /* Copy payload data to the non-paged scratch buffer BEFORE writing.
   * This prevents a TOCTOU race where user-mode could modify the
   * shared page data between validation and the physical write. */
  RtlCopyMemory(g_IpcScratch, dataArea, cmd->Size);

  /* Physical write via CR3 page table translation.
   * Writes use MmMapIoSpace (rare operation — offset dumping is read-only). */
  ULONGLONG cr3 = GetProcessCr3(targetProcess);
  if (!cr3)
    return STATUS_UNSUCCESSFUL;

  return WritePhysicalMemory(cr3, cmd->TargetAddress, g_IpcScratch, cmd->Size);
}

static NTSTATUS HandleReadTolerant(PMEMORY_COMMAND cmd, PVOID dataArea) {
  if (!cmd || !dataArea)
    return STATUS_INVALID_PARAMETER;
  if (!g_IpcScratch)
    return STATUS_DEVICE_NOT_READY;

  if (cmd->Size == 0 || cmd->Size > COMM_DATA_MAXSIZE)
    return STATUS_INVALID_PARAMETER;

  PEPROCESS targetProcess = LookupProcess(cmd->ProcessId);
  if (!targetProcess)
    return STATUS_NOT_FOUND;

  ULONGLONG cr3 = GetProcessCr3(targetProcess);
  if (!cr3)
    return STATUS_UNSUCCESSFUL;

  SIZE_T bytesRead = 0;
  RtlZeroMemory(g_IpcScratch, cmd->Size);

  if (!NT_SUCCESS(ReadPhysicalMemoryTolerant(
          cr3, cmd->TargetAddress, g_IpcScratch, cmd->Size, &bytesRead))) {
    ZeroSharedDataArea(dataArea, cmd->Size);
    return STATUS_UNSUCCESSFUL;
  }

  return CopyScratchToShared(dataArea, cmd->Size);
}

static NTSTATUS HandleGetBase(PMEMORY_COMMAND cmd, PVOID dataArea) {
  if (!cmd || !dataArea)
    return STATUS_INVALID_PARAMETER;

  PEPROCESS targetProcess = LookupProcess(cmd->ProcessId);
  if (!targetProcess)
    return STATUS_NOT_FOUND;

  PVOID base = PsGetProcessSectionBaseAddress(targetProcess);
  if (!base)
    return STATUS_UNSUCCESSFUL;

  *(PULONGLONG)dataArea = (ULONGLONG)base;
  return STATUS_SUCCESS;
}

static NTSTATUS HandleFindCr3(PMEMORY_COMMAND cmd, PVOID dataArea) {
  if (!cmd || !dataArea)
    return STATUS_INVALID_PARAMETER;

  PEPROCESS targetProcess = LookupProcess(cmd->ProcessId);
  if (!targetProcess)
    return STATUS_NOT_FOUND;

  ULONGLONG cr3 = GetProcessCr3(targetProcess);
  if (!cr3)
    return STATUS_UNSUCCESSFUL;

  *(PULONGLONG)dataArea = cr3;
  NOVA_LOG("CR3 for PID %u: 0x%llX (DTB offset 0x%X)", cmd->ProcessId, cr3,
           g_DtbOffset);
  return STATUS_SUCCESS;
}

static NTSTATUS HandleScatterRead(PMEMORY_COMMAND cmd, PVOID dataArea) {
  if (!cmd || !dataArea)
    return STATUS_INVALID_PARAMETER;
  if (!g_IpcScratch)
    return STATUS_DEVICE_NOT_READY;

  ULONG numEntries = (ULONG)cmd->TargetAddress;
  SIZE_T totalSize = cmd->Size;

  if (numEntries == 0 || numEntries > SCATTER_MAX_ENTRIES)
    return STATUS_INVALID_PARAMETER;
  if (totalSize > COMM_DATA_MAXSIZE)
    return STATUS_INVALID_PARAMETER;

  /* Heap-allocate the scatter entries instead of stack.
   * The stack in kernel mode is only 12-24KB — putting ~4KB of entries
   * on it risks overflow, especially with deep call chains.
   * Pool tag g_PoolTag mimics Filter Manager (fltmgr.sys) allocations.
   */
  SIZE_T entriesSize = numEntries * SCATTER_ENTRY_SIZE;
  PSCATTER_ENTRY entries = (PSCATTER_ENTRY)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, entriesSize, g_PoolTag);
  if (!entries)
    return STATUS_INSUFFICIENT_RESOURCES;

  RtlCopyMemory(entries, dataArea, entriesSize);

  PEPROCESS targetProcess = LookupProcess(cmd->ProcessId);
  if (!targetProcess) {
    ExFreePoolWithTag(entries, g_PoolTag);
    return STATUS_NOT_FOUND;
  }

  ULONGLONG cr3 = GetProcessCr3(targetProcess);
  READ_BATCH_METRICS metrics = {0};
  TRANSLATION_CACHE_ENTRY cache = {0};

  /* Execute reads and pack results contiguously */
  SIZE_T offset = 0;
  PUCHAR outBuf = g_IpcScratch;
  RtlZeroMemory(outBuf, totalSize);
  InterlockedIncrement((volatile LONG *)&g_ScatterBatchCount);

  for (ULONG i = 0; i < numEntries;) {
    SIZE_T mergedSize = 0;
    ULONG mergedCount = 1;
    BOOLEAN readOk = FALSE;

    if (entries[i].Size == 0 || entries[i].Size > 0x1000) {
      offset += entries[i].Size;
      i += 1;
      continue;
    }

    mergedSize = entries[i].Size;
    if (offset + mergedSize > COMM_DATA_MAXSIZE)
      break;

    while (i + mergedCount < numEntries) {
      PSCATTER_ENTRY prev = &entries[i + mergedCount - 1];
      PSCATTER_ENTRY next = &entries[i + mergedCount];
      ULONGLONG expectedAddress = prev->Address + prev->Size;
      ULONGLONG firstPage = entries[i].Address & ~0xFFFULL;
      ULONGLONG nextPage = next->Address & ~0xFFFULL;

      if (next->Size == 0 || next->Size > 0x1000)
        break;
      if (next->Address != expectedAddress)
        break;
      if (firstPage != nextPage)
        break;
      if (offset + mergedSize + next->Size > COMM_DATA_MAXSIZE)
        break;

      mergedSize += next->Size;
      mergedCount += 1;
    }

    if (cr3) {
      SIZE_T bytesRead = 0;
      if (NT_SUCCESS(ReadPhysicalMemoryCached(cr3, entries[i].Address,
                                              outBuf + offset, mergedSize,
                                              &bytesRead, &cache, &metrics)) &&
          bytesRead == mergedSize) {
        readOk = TRUE;
      }
    }

    if (!readOk) {
      RtlZeroMemory(outBuf + offset, mergedSize);
    }

    if (mergedCount > 1) {
      metrics.MergedReads += (mergedCount - 1);
    }

    offset += mergedSize;
    i += mergedCount;
  }

  InterlockedAdd((volatile LONG *)&g_ScatterMergedReads, metrics.MergedReads);
  InterlockedAdd((volatile LONG *)&g_ScatterTranslationHits,
                 metrics.TranslationHits);
  InterlockedAdd((volatile LONG *)&g_ScatterTranslationLookups,
                 metrics.TranslationLookups);
  ExFreePoolWithTag(entries, g_PoolTag);
  return CopyScratchToShared(dataArea, totalSize);
}

static NTSTATUS HandleHealthCheck(PMEMORY_COMMAND cmd, PVOID dataArea) {
  if (!dataArea)
    return STATUS_INVALID_PARAMETER;

  /*
   * Health check: Python sends a known magic value, driver echoes it back
   * along with capability flags. This confirms the driver is alive and
   * which features are available.
   *
   * Response layout (40 bytes):
   *   [0..7]   Echo of HEALTH_CHECK_MAGIC (as uint64)
   *   [8..11]  Driver version (uint32): 0x00020003 = v2.3
   *   [12..15] Capability flags (uint32)
   *   [16..19] DTB offset in use (uint32)
   *   [20..23] DTB validated flag (uint32)
   *   [24..27] Scatter batch count
   *   [28..31] Coalesced read count
   *   [32..35] Translation cache hits
   *   [36..39] Translation cache lookups
   */
  UNREFERENCED_PARAMETER(cmd);
  PUCHAR out = (PUCHAR)dataArea;
  RtlZeroMemory(out, 40);

  /* Echo magic */
  *(PULONGLONG)(out + 0) = HEALTH_CHECK_MAGIC;

  /* Driver version */
  *(PULONG)(out + 8) = 0x00020003; /* v2.3 */

  /* Capability flags */
  ULONG caps = 0x01; /* Physical memory read (MmCopyMemory) */
  /* 0x02 reserved (MmCopy fallback removed — too detectable) */
  if (g_DtbValidated)
    caps |= 0x04; /* DTB offset validated */
  caps |= 0x08;   /* Tolerant scanner bulk read */
  *(PULONG)(out + 12) = caps;

  /* DTB info */
  *(PULONG)(out + 16) = g_DtbOffset;
  *(PULONG)(out + 20) = g_DtbValidated ? 1 : 0;
  *(PULONG)(out + 24) =
      (ULONG)InterlockedExchangeAdd((volatile LONG *)&g_ScatterBatchCount, 0);
  *(PULONG)(out + 28) =
      (ULONG)InterlockedExchangeAdd((volatile LONG *)&g_ScatterMergedReads, 0);
  *(PULONG)(out + 32) = (ULONG)InterlockedExchangeAdd(
      (volatile LONG *)&g_ScatterTranslationHits, 0);
  *(PULONG)(out + 36) = (ULONG)InterlockedExchangeAdd(
      (volatile LONG *)&g_ScatterTranslationLookups, 0);

  return STATUS_SUCCESS;
}

/* ─── Context Masked Worker Loop (DPC + WorkItem) ─────────────── */
/*
 * Anti-detection:
 * Instead of spinning KeDelayExecutionThread in a continuous system thread
 * (which leaves our unbacked memory on the call stack 100% of the time, easily
 * caught by BattlEye/EAC NMI stack walking), we use a Timer + DPC + WorkItem.
 *
 * When idle, our driver has NO stack frame at all. It effectively disappears.
 * Upon timer expiration, a system worker thread executes our poll, handles it
 * in ~1 microsecond, queues the next timer, and returns fully to ntoskrnl.
 */
static VOID PollWorkItemRoutine(PVOID Context) {
  UNREFERENCED_PARAMETER(Context);

  if (!g_Running) {
    KeSetEvent(&g_UnloadEvent, 0, FALSE);
    return;
  }

  PMEMORY_COMMAND cmd = (PMEMORY_COMMAND)g_SharedPage;
  PVOID dataArea = (PUCHAR)g_SharedPage + COMM_HEADER_SIZE;

  /* Enter critical region to prevent kernel APC delivery while executing our
   * payload */
  KeEnterCriticalRegion();

  if (cmd->MagicCode == COMMAND_MAGIC) {
    NOVA_LOG("PollWorkItem: Received command, Instruction: %d",
             cmd->Instruction);
    NTSTATUS status;

    switch (cmd->Instruction) {
    case COMMAND_READ:
      status = HandleRead(cmd, dataArea);
      break;
    case COMMAND_WRITE:
      status = HandleWrite(cmd, dataArea);
      break;
    case COMMAND_GETBASE:
      status = HandleGetBase(cmd, dataArea);
      break;
    case COMMAND_FINDCR3:
      status = HandleFindCr3(cmd, dataArea);
      break;
    case COMMAND_SCATTER_READ:
      status = HandleScatterRead(cmd, dataArea);
      break;
    case COMMAND_READ_TOLERANT:
      status = HandleReadTolerant(cmd, dataArea);
      break;
    case COMMAND_HEALTH_CHECK:
      status = HandleHealthCheck(cmd, dataArea);
      break;
    default:
      status = STATUS_INVALID_PARAMETER;
      break;
    }

    cmd->Status =
        status == STATUS_SUCCESS ? CMD_STATUS_COMPLETE : CMD_STATUS_ERROR;
    cmd->MagicCode = 0; /* Clear magic to show we're done */
  }

  KeLeaveCriticalRegion();

  /* Re-queue timer for the next poll using our DPC */
  if (g_Running) {
    LARGE_INTEGER delay;
    delay.QuadPart = -1000LL; /* 100us in 100ns units */
    KeSetTimer(&g_PollTimer, delay, &g_PollDpc);
  } else {
    KeSetEvent(&g_UnloadEvent, 0, FALSE);
  }
}

static VOID PollTimerDpc(PKDPC Dpc, PVOID DeferredContext,
                         PVOID SystemArgument1, PVOID SystemArgument2) {
  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(DeferredContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  if (g_Running) {
#pragma warning(suppress                                                       \
                : 4996) /* ExInitializeWorkItem/ExQueueWorkItem are            \
                           technically deprecated but widely supported */
    ExInitializeWorkItem(&g_PollWorkItem, PollWorkItemRoutine, NULL);
#pragma warning(suppress : 4996)
    ExQueueWorkItem(&g_PollWorkItem, DelayedWorkQueue);
  } else {
    KeSetEvent(&g_UnloadEvent, 0, FALSE);
  }
}

/* ─── Anti-Detection: ETHREAD Spoof ──────────────────────── */
/*
 * Anti-cheats (EAC, BattlEye) enumerate system threads and check
 * ETHREAD->StartAddress to find threads belonging to suspicious drivers.
 * If the start address doesn't point inside a known legitimate module,
 * the thread (and its driver) is flagged.
 *
 * We scan the ETHREAD struct for all instances of our real start address
 * and replace them with a common ntoskrnl export (KeWaitForMultipleObjects).
 * This covers StartAddress, Win32StartAddress, and any other copies.
 */
static VOID SpoofThreadStartAddress(HANDLE threadHandle, PVOID realStartAddr) {
  PVOID threadObj = NULL;
  PVOID spoofAddr = NULL;
  UNICODE_STRING funcName;

  if (!NT_SUCCESS(ObReferenceObjectByHandle(
          threadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &threadObj, NULL)))
    return;

  /* Use a common ntoskrnl export as the fake start address */
  RtlInitUnicodeString(&funcName, L"KeWaitForMultipleObjects");
  spoofAddr = MmGetSystemRoutineAddress(&funcName);
  if (!spoofAddr) {
    RtlInitUnicodeString(&funcName, L"KeWaitForSingleObject");
    spoofAddr = MmGetSystemRoutineAddress(&funcName);
  }
  if (!spoofAddr) {
    ObDereferenceObject(threadObj);
    return;
  }

  /* Scan ETHREAD for all instances of our real start address.
   * This covers StartAddress, Win32StartAddress, and any internal copies.
   * Limit to 0x700 bytes — covers all needed fields across Win10 1507
   * through Win11 24H2. Validate each read to avoid page faults. */
  PUCHAR bytes = (PUCHAR)threadObj;
  for (ULONG i = 0; i <= 0x700 - sizeof(PVOID); i += sizeof(PVOID)) {
    if (!MmIsAddressValid(bytes + i))
      break;
    if (*(PVOID *)(bytes + i) == realStartAddr)
      *(PVOID *)(bytes + i) = spoofAddr;
  }

  ObDereferenceObject(threadObj);
  NOVA_LOG("ETHREAD start address spoofed to %p", spoofAddr);
}

/* ─── Anti-Detection: Module Name Wipe ───────────────────── */
/*
 * BattlEye's module scanner identifies drivers by name string in the
 * KLDR_DATA_TABLE_ENTRY. We zero the BaseDllName and FullDllName buffers
 * while preserving InLoadOrderLinks (unlinking triggers PatchGuard BSOD
 * and breaks RtlLookupFunctionEntry for exception unwinding).
 */
typedef struct _KLDR_DATA_TABLE_ENTRY_MIN {
  LIST_ENTRY InLoadOrderLinks; /* +0x000 */
  PVOID ExceptionTable;        /* +0x010 */
  ULONG ExceptionTableSize;    /* +0x018 */
  ULONG Pad0;                  /* +0x01C */
  PVOID GpValue;               /* +0x020 */
  PVOID NonPagedDebugInfo;     /* +0x028 */
  PVOID DllBase;               /* +0x030 */
  PVOID EntryPoint;            /* +0x038 */
  ULONG SizeOfImage;           /* +0x040 */
  ULONG Pad1;                  /* +0x044 */
  UNICODE_STRING FullDllName;  /* +0x048 */
  UNICODE_STRING BaseDllName;  /* +0x058 */
} KLDR_DATA_TABLE_ENTRY_MIN, *PKLDR_DATA_TABLE_ENTRY_MIN;

static VOID HideDriverFromModuleList(PDRIVER_OBJECT DriverObject) {
  if (!DriverObject || !DriverObject->DriverSection)
    return;

  PKLDR_DATA_TABLE_ENTRY_MIN ldr =
      (PKLDR_DATA_TABLE_ENTRY_MIN)DriverObject->DriverSection;

  /* Zero name strings — BE's scanner matches by name, not by raw address range
   */
  if (ldr->BaseDllName.Buffer) {
    RtlZeroMemory(ldr->BaseDllName.Buffer, ldr->BaseDllName.Length);
    ldr->BaseDllName.Length = 0;
    ldr->BaseDllName.MaximumLength = 0;
    ldr->BaseDllName.Buffer = NULL;
  }
  if (ldr->FullDllName.Buffer) {
    RtlZeroMemory(ldr->FullDllName.Buffer, ldr->FullDllName.Length);
    ldr->FullDllName.Length = 0;
    ldr->FullDllName.MaximumLength = 0;
    ldr->FullDllName.Buffer = NULL;
  }

  NOVA_LOG("Module name strings wiped from LDR entry");
}

/* ─── Anti-Detection: PE Header Wipe ─────────────────────── */
/*
 * AC memory scanners search for MZ/PE signatures at driver base addresses.
 * We create a writable MDL alias of the driver's first page (PE header)
 * and zero it. The driver's code sections remain intact.
 */
static VOID WipePEHeader(PDRIVER_OBJECT DriverObject) {
  if (!DriverObject || !DriverObject->DriverStart)
    return;

  PMDL headerMdl =
      IoAllocateMdl(DriverObject->DriverStart, PAGE_SIZE, FALSE, FALSE, NULL);
  if (!headerMdl)
    return;

  MmBuildMdlForNonPagedPool(headerMdl);

  PVOID mapped = MmMapLockedPagesSpecifyCache(
      headerMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

  if (mapped) {
    RtlZeroMemory(mapped, PAGE_SIZE);
    MmUnmapLockedPages(mapped, headerMdl);
    NOVA_LOG("PE header wiped (first page zeroed)");
  }

  IoFreeMdl(headerMdl);
}

/* ─── Driver Entry / Unload ───────────────────────────────── */

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  NOVA_LOG("Unloading...");

  g_Running = FALSE;

  /* Stop the primary polling timer explicitly */
  g_Running = FALSE;
  KeCancelTimer(&g_PollTimer);

  /* Wait for any currently executing WorkItems to notice g_Running == FALSE and
   * signal g_UnloadEvent */
  KeWaitForSingleObject(&g_UnloadEvent, Executive, KernelMode, FALSE, NULL);

  /* Release cached EPROCESS */
  if (g_CachedProcess) {
    ObDereferenceObject(g_CachedProcess);
    g_CachedProcess = NULL;
    g_CachedPid = 0;
  }

  if (g_SharedPage) {
    MmUnmapViewInSystemSpace((PVOID)g_SharedPage);
    g_SharedPage = NULL;
  }
  if (g_IpcScratch) {
    ExFreePoolWithTag(g_IpcScratch, g_PoolTag);
    g_IpcScratch = NULL;
  }
  if (g_SectionHandle) {
    ZwClose(g_SectionHandle);
    g_SectionHandle = NULL;
  }

  NOVA_LOG("Unloaded.");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                     PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);
  UNREFERENCED_PARAMETER(DriverObject);
  NTSTATUS status;

  /* ─── Per-boot entropy initialization ─────────────────────── */
  /*
   * Generate machine-unique, boot-unique values for:
   *   1. Pool tag — prevents pool tag scanning fingerprints
   *   2. Section name — prevents static GUID fingerprinting
   *
   * Entropy sources:
   *   - KeQueryPerformanceCounter: high-resolution boot-time counter
   *   - KeQuerySystemTimePrecise: wall-clock time with microsecond precision
   *   - KeGetCurrentProcessorNumberEx: adds per-CPU jitter
   *
   * The goal is NOT cryptographic randomness — it's sufficient that
   * every boot produces a different name so BattlEye can't signature
   * a single static string.
   */
  {
    LARGE_INTEGER perfCounter, perfFreq, sysTime;
    perfCounter = KeQueryPerformanceCounter(&perfFreq);
    KeQuerySystemTimePrecise(&sysTime);
    ULONG processorNumber = KeGetCurrentProcessorNumberEx(NULL);

    /* Mix entropy into a 64-bit seed */
    ULONGLONG seed = (ULONGLONG)perfCounter.QuadPart ^
                     (ULONGLONG)sysTime.QuadPart ^
                     ((ULONGLONG)processorNumber << 32) ^
                     ((ULONGLONG)perfFreq.QuadPart >> 7);

    /* Derive pool tag from lower 32 bits (ensure no zero bytes) */
    ULONG tag = (ULONG)(seed & 0xFFFFFFFF);
    PUCHAR tagBytes = (PUCHAR)&tag;
    for (int i = 0; i < 4; i++) {
      if (tagBytes[i] == 0)
        tagBytes[i] = (UCHAR)(0x41 + (i * 17));
    }
    g_PoolTag = tag;

    /* Generate section name:
     * \BaseNamedObjects\Global\{wdf-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
     * Format as a GUID to blend with COM/WinRT section objects. */
    ULONG a = (ULONG)(seed >> 32);
    USHORT b = (USHORT)(seed >> 16);
    USHORT c = (USHORT)(seed);
    USHORT d = (USHORT)(seed >> 48);
    /* Use perfCounter low bits for the last 12 hex chars */
    ULONGLONG tail = perfCounter.QuadPart ^ (sysTime.QuadPart >> 3);
    ULONG e1 = (ULONG)(tail >> 16);
    USHORT e2 = (USHORT)(tail);

    RtlStringCchPrintfW(
        g_SectionName, COMM_SECTION_NAME_MAXLEN,
        L"\\BaseNamedObjects\\Global\\{wdf-%08x-%04x-%04x-%04x-%08x%04x}", a, b,
        c, d, e1, e2);

    NOVA_LOG("Entropy pool tag: 0x%08X", g_PoolTag);
    NOVA_LOG("Section name: %ws", g_SectionName);
  }

  /* Create shared section (uses g_SectionName generated above) */
  status = CreateAndMapSharedSection();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  /* Initialize globals */
  g_Running = TRUE;

  /* Allocate nonpaged scratch buffer for IPC read commands.
   * HandleRead / HandleReadTolerant / HandleScatterRead all read into
   * this scratch buffer first, then copy to the shared page.  Without it
   * every read returns STATUS_DEVICE_NOT_READY and 0 bytes. */
  g_IpcScratch = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, COMM_DATA_MAXSIZE,
                                         g_PoolTag);
  if (!g_IpcScratch) {
    NOVA_LOG("Failed to allocate IPC scratch buffer (%u bytes)",
             COMM_DATA_MAXSIZE);
    MmUnmapViewInSystemSpace((PVOID)g_SharedPage);
    g_SharedPage = NULL;
    if (g_SectionHandle) {
      ZwClose(g_SectionHandle);
      g_SectionHandle = NULL;
    }
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory(g_IpcScratch, COMM_DATA_MAXSIZE);

  /* Create Unload Event */
  KeInitializeEvent(&g_UnloadEvent, NotificationEvent, FALSE);

  /* Initialize Timer and DPC */
  KeInitializeTimer(&g_PollTimer);
  KeInitializeDpc(&g_PollDpc, PollTimerDpc, NULL);

  /* Start the polling loop (100us intervals) */
  LARGE_INTEGER interval;
  interval.QuadPart = -1000LL;
#pragma warning(suppress : 4996)
  ExInitializeWorkItem(&g_PollWorkItem, PollWorkItemRoutine, NULL);
  KeSetTimer(&g_PollTimer, interval, &g_PollDpc);

  NOVA_LOG("Timer and WorkItem started successfully");

  /* Anti-detection: hide module name and PE header */
  HideDriverFromModuleList(DriverObject);
  WipePEHeader(DriverObject);

  NOVA_LOG("Kernel driver v2.3 loaded successfully with worker thread.");
  return STATUS_SUCCESS;
}
