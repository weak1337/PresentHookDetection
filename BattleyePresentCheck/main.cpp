#include <Windows.h>
#include <iostream>
#include <unordered_map>
#include <Winternl.h>
#include <tuple>
#include <d3d11.h>
#include "utils.h"


typedef HRESULT(__stdcall* D3D11PresentHook) (IDXGISwapChain* This, UINT SyncInterval, UINT Flags);
volatile static D3D11PresentHook oPresent = NULL;
uintptr_t** present_pointer;
IDXGISwapChain* globalchain;
extern "C" HRESULT __stdcall hookD3D11Present(IDXGISwapChain * This, UINT SyncInterval, UINT Flags)
{
	printf("[>] Handler called! Saving swapchain\n");
	globalchain = This;
	*present_pointer = (uintptr_t*)oPresent;
	return oPresent(This, SyncInterval, Flags);
}


std::unordered_map<std::string, std::tuple<std::string,int>>modules{
	{ "gameoverlayrenderer64.dll", std::tuple<std::string,int>("33 F6 83 E5 F7 44 8B C5 8B D6 49 8B CE FF 15", 15) },
	{ "DiscordHook64.dll",  std::tuple<std::string,int>("48 89 D9 89 FA 41 89 F0 FF 15", 10) },
	{ "overlay64.dll",  std::tuple<std::string,int>("48 8B 5C 24 40 44 8B 44 24 30 8B 54 24 38 48 8B CB FF 15", 19) },
	{ "DiscordHook64.dll",  std::tuple<std::string,int>("44 8B C7 8B D6 48 8B CB FF 15", 10) }
};

bool func_anomaly(uintptr_t& present) {
	bool found_anomaly = false;
	
	while (true) {


		while (true) { 
			while (*(BYTE*)present == 0xE9) { 
				if (*(DWORD*)(present + 5) == 0xCCCCCCCC)
					found_anomaly = true;
				present += *(signed int*)(present + 1) + 5;
			}
			if (*(WORD*)present != 0x25FF)
				break;
			present = *(uintptr_t*)(present + 6);
		}

		if (*(WORD*)present != 0xB848 || *((WORD*)present + 5) != 0xE0FF)
			break;
		present = *(uintptr_t*)(present + 2);
		found_anomaly = true;
	}
	return found_anomaly;
}

bool find_memory_anomaly(uintptr_t present) {
	bool found_anomaly = false;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	MEMORY_BASIC_INFORMATION mbi2 = { 0 };
	NTSTATUS v27 = NtQueryVirtualMemory((HANDLE) - 1, (LPVOID)present, MemoryBasicInformation, &mbi, 48i64, 0) < 0;
	NTSTATUS v7 = v27;
	NTSTATUS v28;
	bool v31 = v27
		|| mbi.State != MEM_COMMIT
		|| mbi.Type != MEM_IMAGE
		&& (mbi.Type != MEM_PRIVATE
			|| mbi.State != MEM_FREE
			|| *((uintptr_t*)present + 20) != 0xEBFFFFFF41058D48ui64
			|| (present = *((uintptr_t*)present - 3),
				v28 = NtQueryVirtualMemory((HANDLE) - 1i64, (LPVOID)present, MemoryBasicInformation, &mbi2, 48i64, 0) < 0,
				v7 = v28)
			|| mbi2.State != MEM_COMMIT
			|| mbi2.Type != MEM_IMAGE)
		|| mbi.Protect != 16 && mbi.Protect != 32 && mbi.Protect != 64 && mbi.Protect != 128
		|| *(uintptr_t*)present == 0x74894808245C8948i64
		&& (*((uintptr_t*)present + 1) == 0x4140EC8348571024i64
			|| *((uintptr_t*)present + 1) == 0x5518247C89481024i64)
		|| *(uintptr_t*)present == 0x57565520245C8948i64
		|| *(uintptr_t*)present == 0x4157551824748948i64
		|| *(uintptr_t*)present == 0x8D48564157565540ui64
		|| *(DWORD*)present == 1220840264 && *((WORD*)present + 2) == 22665
		|| *(uintptr_t*)present == 0x5741564157565340i64
		|| *(uintptr_t*)present == 0x5741564155C48B48i64
		|| *(uintptr_t*)present == 0x4156415441575540i64;
	found_anomaly = v31;
	return found_anomaly;
}

int main() {
	bool reported = false;

	//General report
	{

		uintptr_t base = (uintptr_t)GetModuleHandleA("dxgi.dll");
		if (base) {
			PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
			PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
			DWORD code_base = nt->OptionalHeader.BaseOfCode;
			DWORD code_size = nt->OptionalHeader.SizeOfCode;
			uintptr_t code_start = code_base + base;
			uintptr_t sig_base = utils::scanpattern(code_start, code_size, "48 C7 40 B8 FE FF FF FF 48 89 58 18");
			if (sig_base) {
				uintptr_t swap_chain = sig_base + *(signed int*)(sig_base + 0x25) + 0x29;
				uintptr_t present = *(uintptr_t*)(swap_chain + 0x40);
				MEMORY_BASIC_INFORMATION mbi_globalchain = { 0 };
				NTSTATUS globalchainstatus = NtQueryVirtualMemory((HANDLE)-1, (PVOID)swap_chain, MemoryBasicInformation, (PVOID)&mbi_globalchain, sizeof(mbi_globalchain), 0);
				if (globalchainstatus || func_anomaly(present)) {
					reported = true;
					printf("[!!!] Anomaly at: %p\n", present);
				}

				else
				{
					printf("[>] No anomalys found jump chain ends at %p\n", present);
					printf("[>] Verifying memory!\n");
					if (find_memory_anomaly(present)) {
						printf("[!!!] Memory anomaly at destination!\n");
						reported = true;
					}

				}
				printf("==GENERAL REPORT==\n");
				printf("Report: %x %x\n", 0x47, 0x1);
				printf("Present: %p\n", present);
				printf("First 32 bytes...\n");
				printf("Allocation base: %p\n", mbi_globalchain.AllocationBase);
				printf("Base address: %p\n", mbi_globalchain.BaseAddress);
			}

		
		}

	}
	
	//Module specific detections
	int idx = 0;
	for (auto pair : modules) {
		if (uintptr_t base = (uintptr_t)GetModuleHandleA(pair.first.c_str())) {
			present_pointer = 0;
			PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
			PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
			DWORD code_base = nt->OptionalHeader.BaseOfCode;
			DWORD code_size = nt->OptionalHeader.SizeOfCode;
			uintptr_t code_start = code_base + base;

			uintptr_t sig_base = utils::scanpattern(code_start, code_size, std::get<0>(pair.second).c_str());
			if (!sig_base)
				continue;
			printf("[>] Sig at %p\n", sig_base);
			if (idx == 0) { //gameoverlayrenderer64.dll
				uintptr_t jmp_dst = sig_base - 0x45;
				if (*(BYTE*)jmp_dst == 0xE8 &&
					(jmp_dst += *(signed int*)(jmp_dst + 1) + 5, *(DWORD*)jmp_dst != 0x83485340)) {
					present_pointer = (uintptr_t**)&jmp_dst;
				}

			}
			else if (idx == 1) { //DiscordHook64.dll
				uintptr_t jmp_dst = sig_base - 0x13;
				if (*(BYTE*)jmp_dst == 0xE8 &&
					(jmp_dst += *(signed int*)(jmp_dst + 1) + 5, *(BYTE*)jmp_dst == 0xE9) &&
					(jmp_dst += *(signed int*)(jmp_dst + 1) + 15, *(BYTE*)jmp_dst == 0xE9) &&
					(jmp_dst += *(signed int*)(jmp_dst + 1) + 5, *(BYTE*)jmp_dst != 0x56535540)
					) {
					present_pointer = (uintptr_t**)&jmp_dst;
				}

				else {
					jmp_dst = sig_base - 0xA6;
					if (*(BYTE*)jmp_dst == 0xE9 &&
						(jmp_dst += *(signed int*)(jmp_dst + 1) + 5, *(BYTE*)jmp_dst == 0xE9) &&
						(jmp_dst += *(signed int*)(jmp_dst + 1) + 6, **(uintptr_t**)jmp_dst == 0x2454891824448944)
						) {
						present_pointer = (uintptr_t**)jmp_dst;
					}
				}
			}
			
			if(!present_pointer) { //overlay64.dll or DiscordHook64.dll
				present_pointer = (uintptr_t**)(sig_base + std::get<1>(pair.second)+  *(DWORD*)(sig_base + std::get<1>(pair.second)) + 4);
			}
			if (present_pointer  && *present_pointer) {

				MEMORY_BASIC_INFORMATION mbi = { 0 };
				NTSTATUS status = NtQueryVirtualMemory((HANDLE) - 1, *present_pointer, MemoryBasicInformation, (PVOID) & mbi, sizeof(mbi), 0);
				if (status || mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || mbi.Protect != PAGE_EXECUTE_READWRITE || *(DWORD*)(*present_pointer) == 0x50C03148) { //xor rax, rax push rax
					printf("[!!!] Present is invalid memory! %p %p\n", status, &mbi);
					reported = true;
				
				}

				printf("[>] Present pointer in %s at %p\n", pair.first.c_str(), present_pointer);

				oPresent = (D3D11PresentHook)*present_pointer;
				*present_pointer = (uintptr_t*)hookD3D11Present;

				Sleep(1000); //Sleep and hope that present got called once
				printf("[>] Found SwapChain at %p\n", globalchain);
				MEMORY_BASIC_INFORMATION mbi_globalchain = { 0 };
				NTSTATUS globalchainstatus = NtQueryVirtualMemory((HANDLE)-1, globalchain, MemoryBasicInformation, (PVOID)&mbi_globalchain, sizeof(mbi_globalchain), 0);
				uintptr_t present_from_vtable = *(uintptr_t*)(*(uintptr_t*)(globalchain)+0x40);
				if (globalchainstatus || func_anomaly(present_from_vtable)) {
					reported = true;
					printf("[!!!] Anomaly at: %p\n", present_from_vtable);
				}
				
				else
				{
					printf("[>] No anomalys found jump chain ends at %p\n", present_from_vtable);
					printf("[>] Verifying memory!\n");
					if (find_memory_anomaly(present_from_vtable)) {
						printf("[!!!] Memory anomaly at destination!\n");
						reported = true;
					}

				}
			}
		}
		idx++;
	}
	if (reported) {
		printf("[!!!] You received reports!\n");
	}
	else {
		printf("[>] No reports! You're good to go\n");
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH: {
		AllocConsole();
		FILE* f;
		freopen_s(&f, "CONOUT$", "w", stdout);
		main();
		break;
	}

	}
	return TRUE;
}
