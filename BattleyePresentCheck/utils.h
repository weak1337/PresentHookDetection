#pragma once
#include <Windows.h>
#include <vector>
namespace utils {
    uintptr_t scanpattern(uintptr_t base, int size, const char* signature);
}
using MEMORY_INFORMATION_CLASS = enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
};
extern "C" NTSTATUS DECLSPEC_IMPORT NTAPI NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);