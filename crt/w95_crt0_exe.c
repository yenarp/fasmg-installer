#define WIN32_LEAN_AND_MEAN
#include <stddef.h>
#include <windows.h>

typedef LPSTR(__stdcall *PFN)(void);

void __main(void) {}

__attribute__((weak)) int main(int argc, char **argv);

static LPSTR get_cmdline_fallback(void) {
	HMODULE hK = GetModuleHandleA("KERNEL32.DLL");
	if (!hK)
		hK = GetModuleHandleA(NULL);

	PFN p = (PFN)GetProcAddress(hK, "GetCommandLineA");
	return p ? p() : (LPSTR) "";
}

static int call_main(void) {
	char *argv0 = NULL;
	char *argv1[1] = {0};

	char buf[MAX_PATH];
	DWORD n = GetModuleFileNameA(NULL, buf, sizeof(buf));
	if (n && n < sizeof(buf))
		argv0 = buf;

	argv1[0] = argv0;
	return main ? main(argv0 ? 1 : 0, argv0 ? argv1 : NULL) : 0;
}

void __stdcall mainCRTStartup(void) {
	int rc = 0;
	rc = call_main();

	ExitProcess((UINT)rc);
}
