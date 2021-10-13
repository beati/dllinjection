#include "dll.h"

#include <windows.h>

DWORD WINAPI mainThread(LPVOID param) {
    OnProcessAttach();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE dll, DWORD reason, LPVOID reserved) {
    switch (reason) {
	case DLL_PROCESS_ATTACH: {
        HANDLE hThread = CreateThread(NULL, 0, mainThread, NULL, 0, NULL);
    } break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_DETACH:
    case DLL_THREAD_ATTACH:
        break;
    }
    return TRUE;
}
