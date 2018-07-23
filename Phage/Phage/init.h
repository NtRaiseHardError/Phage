#pragma once
#ifndef __INIT_H__
#define __INIT_H__

#include <TlHelp32.h>

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

pfnLoadLibraryA fnLoadLibraryA;
pfnGetProcAddress fnGetProcAddress;

pfnCreateToolhelp32Snapshot fnCreateToolhelp32Snapshot;
pfnProcess32FirstW fnProcess32FirstW;
pfnProcess32NextW fnProcess32NextW;
pfnOpenProcess fnOpenProcess;
pfnCloseHandle fnCloseHandle;
pfnIsWow64Process fnIsWow64Process;
pfnGetProcessHeap fnGetProcessHeap;
pfnHeapAlloc fnHeapAlloc;
pfnGetModuleFileNameW fnGetModuleFileNameW;
pfnVirtualAllocEx fnVirtualAllocEx;
pfnWriteProcessMemory fnWriteProcessMemory;
pfnCreateRemoteThread fnCreateRemoteThread;
pfnHeapFree fnHeapFree;
pfnGetLastError fnGetLastError;
pfnExitProcess fnExitProcess;
pfnGetNativeSystemInfo fnGetNativeSystemInfo;
pfnWaitForSingleObject fnWaitForSingleObject;
pfnGetModuleHandleW fnGetModuleHandleW;
pfnCreateProcessW fnCreateProcessW;

// shwlapi
pfnStrStrIW fnStrStrIW;

// user32
#ifdef _DEBUG
pfnwvsprintfW fnwvsprintfW;
pfnMessageBoxW fnMessageBoxW;
#endif // _DEBUG

BOOL BaseRelocate(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh, DWORD dwDelta);

#endif // !__INIT_H__
