#pragma once
#ifndef __HOOK_H__
#define __HOOK_H__

// hooking variables
BYTE bCreateSavedByte;
FARPROC fpCreateProcessW;

LONG WINAPI MyUnhandledExceptionFilter(LPEXCEPTION_POINTERS lpException);

#endif // !__HOOK_H__
