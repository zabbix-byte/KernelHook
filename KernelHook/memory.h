#pragma once
#include "definitions.h"

typedef struct _NULL_MEMORY
{
	void* buffer_adddress;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN req_base;
	void* output;
	const char* module_name;
	ULONG64 base_address;
} NULL_MEMORY;


PVOID GetSystemModuleBase(const char* module_name);
PVOID GetSystemModuleExport(const char* module_name, LPCSTR routine_name);
bool WriteMemory(void* address, void* buffer, size_t size);
bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size);
ULONG GetModuleBaseX64(PEPROCESS proc, UNICODE_STRING module_name);
bool ReadKernelMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
bool WriteKernelMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);