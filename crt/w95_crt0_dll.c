
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__attribute__((weak)) BOOL __stdcall DllMain(HINSTANCE, DWORD, LPVOID);

BOOL __stdcall _DllMainCRTStartup(HINSTANCE h, DWORD r, LPVOID p) {
	return DllMain(h, r, p);
}
