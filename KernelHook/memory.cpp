#include "memory.h"

PVOID GetSystemModuleBase(const char* module_name) 
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return NULL;
																										// NULL
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return NULL;

	if (!modules)
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, module_name) == 0)
		{
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);
	
	if (module_base <= NULL)
		return NULL;

	return module_base;
}

PVOID GetSystemModuleExport(const char* module_name, LPCSTR routine_name)
{
	PVOID lp_module = GetSystemModuleBase(module_name);

	if (!lp_module)
		return NULL;

	return RtlFindExportedRoutineByName(lp_module, routine_name);
}

bool WriteMemory(void* address, void* buffer, size_t size)
{
	if (!RtlCopyMemory(address, buffer, size))
		return false;

	return true;
}

bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size)
{
	PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!mdl)
		return false;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

	WriteMemory(mapping, buffer, size);

	MmUnmapLockedPages(mapping, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return true;
}

ULONG GetModuleBaseX64(PEPROCESS proc, UNICODE_STRING module_name)
{
	PPEB p_peb = PsGetProcessPeb(proc);

	if (!p_peb)
		return NULL;

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA p_ldr = (PPEB_LDR_DATA)p_peb->Ldr;

	if (!p_ldr)
	{
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)p_ldr->ModuleListLoadOrder.Flink; list != &p_ldr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY p_entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&p_entry->BaseDllName, &module_name, TRUE) == NULL)
		{
			ULONG64 base_addr = (ULONG64)p_entry->DllBase;
			KeUnstackDetachProcess(&state);
			return base_addr;
		}
	}

	KeUnstackDetachProcess(&state);
	return NULL;
}

bool ReadKernelMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &bytes);

	if (!NT_SUCCESS(status))
		return false;
	return true;
}

bool WriteKernelMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	KAPC_STATE state;
	KeStackAttachProcess((PEPROCESS)process, &state);

	MEMORY_BASIC_INFORMATION info;

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation(), &info, sizeof(info), NULL);

	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if ((info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_EXECUTE_WRITECOPY) 
		|| (info.Protect & PAGE_READONLY) || (info.Protect & PAGE_WRITECOPY))
	{
		RtlCopyMemory((void*)address, buffer, size);
	}

	KeUnstackDetachProcess(&state);
	return true;

}