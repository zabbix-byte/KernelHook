#pragma once
#include "definitions.h"

PVOID GetSystemModuleBase(const char* module_name);
PVOID GetSystemModuleExport(const char* module_name, LPCSTR routine_name);
bool WriteMemory(void* address, void* buffer, size_t size);
bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size);
