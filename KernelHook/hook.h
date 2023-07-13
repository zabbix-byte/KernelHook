#pragma once
#include "memory.h"

namespace ztrunkhook
{
	bool CallKernel(void* kernel_function_address);
	NTSTATUS Handle(PVOID called_param);
}