#include <Windows.h>
#include <Shlwapi.h>

#include "hook.h"
#include "init.h"

BYTE bCreateSavedByte;
FARPROC fpCreateProcessW = NULL;

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