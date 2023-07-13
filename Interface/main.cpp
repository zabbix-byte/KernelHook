#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>
#include <string> 


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

uintptr_t base_address = 0;
std::uint32_t process_id = 0;

template<typename ... Arg>
uint64_t call_hook(const Arg ... args)
{
	void* hooked_func = GetProcAddress(LoadLibrary("win32u.dll"), "NtQueryCompositionSurfaceStatistics");

	auto func = static_cast<uint64_t(_stdcall*)(Arg...)>(hooked_func);

	return func(args ...);
}

struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;


std::uint32_t GetProcessID(std::string_view process_name)
{
	PROCESSENTRY32 processentry;
	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return NULL;

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE)
	{
		if (process_name.compare(processentry.szExeFile) == NULL)
		{
			return processentry.th32ProcessID;
		}
	}

	return NULL;
}

static ULONG64 GetModuleBaseAddres(const char* module_name)
{
	NULL_MEMORY instructions = { 0 };
	instructions.pid = process_id;
	instructions.req_base = TRUE;
	instructions.read = FALSE;
	instructions.write = FALSE;
	instructions.module_name = module_name;

	call_hook(&instructions);

	ULONG64 base = NULL;
	base = instructions.base_address;
	return base;
}

template <class T>
T Read(UINT_PTR read_address)
{
	T response{};
	NULL_MEMORY instructions;
	instructions.pid = process_id;
	instructions.size = sizeof(T);
	instructions.address = read_address;
	instructions.read = TRUE;
	instructions.write = FALSE;
	instructions.req_base = FALSE;
	instructions.output = &response;
	call_hook(&instructions);

	return response;
}

bool WriteMemory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
	NULL_MEMORY instructions;
	instructions.pid = process_id;
	instructions.size = write_size;
	instructions.address = write_address;
	instructions.buffer_adddress = (void*)source_address;
	instructions.read = FALSE;
	instructions.write = TRUE;
	instructions.req_base = FALSE;

	call_hook(&instructions);
	return true;
}

template <typename S>
bool Write(UINT_PTR write_address, const S& value)
{
	return WriteMemory(write_address, (UINT_PTR)&value, sizeof(S));
}

int main()
{
	// test
	process_id = GetProcessID("IMVUClient.exe");
	printf("%s \n", std::to_string(process_id));
	base_address = GetModuleBaseAddres("IMVUClient.exe");

	if (!base_address)
	{
		printf("me cago el la puta");
	}
	else {
		printf("yeeeeeeeeeeeee");
	}

	return 0;
}