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
	return STATUS_SUCCESS;
}