#include "hook.h"

bool ztrunkhook::CallKernel(void* kernel_function_address)
{
	if (!kernel_function_address)
		return false;

	// hooks https://j00ru.vexillium.org/syscalls/win32k/64/
	PVOID* function = reinterpret_cast<PVOID*>(GetSystemModuleExport(
		"\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", 
		"NtQueryCompositionSurfaceStatistics"
	));

	if (!function)
		return false;

	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// beee carefull with this this is what the anticheat wait to do
	// change the signature of this and you gone be indetectable 
	// this on easyanticheat
	BYTE shell_code[] = { 0x48, 0xB8 }; // mov rax, xxx
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; // jmp rax

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	WriteToReadOnlyMemory(function, &orig, sizeof(orig));

	return true;

}	

NTSTATUS ztrunkhook::Handle(PVOID called_param)
{
	NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;

	if (instructions->req_base != FALSE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instructions->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
		ULONG64 base_address64 = NULL;
		base_address64 = GetModuleBaseX64(process, ModuleName);
		instructions->base_address = base_address64;
		RtlFreeUnicodeString(&ModuleName);
	}

	if (instructions->write != FALSE)
	{
		// checking if the address is in a valid memory range
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			PVOID kernel_buff = ExAllocatePool(NonPagedPool, instructions->size);

			if (!kernel_buff)
				return STATUS_UNSUCCESSFUL;

			if (!memcpy(kernel_buff, instructions->buffer_adddress, instructions->size))
				return STATUS_UNSUCCESSFUL;

			PEPROCESS process;
			PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
			WriteKernelMemory((HANDLE)instructions->pid, instructions->address, kernel_buff, instructions->size);
			ExFreePool(kernel_buff);
		}
	}

	if (instructions->read != FALSE)
	{
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			ReadKernelMemory((HANDLE)instructions->pid, instructions->address, instructions->output, instructions->size);
		}
	}

	return STATUS_SUCCESS;
}