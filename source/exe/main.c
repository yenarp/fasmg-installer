#include <windows.h>

#include <commdlg.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE_NAME "fasmg"

extern const unsigned char installer_archive[];
extern const size_t installer_archive_size;

typedef LRESULT(WINAPI *PFNSENDMESSAGEA)(HWND, UINT, WPARAM, LPARAM);

static PFNSENDMESSAGEA pSendMessageA = NULL;

static int ensure_SendMessageA_loaded(void) { /* windows 95 hack */
	if (pSendMessageA)
		return 1;

	HMODULE hUser32 = LoadLibraryA("USER32.DLL");
	if (!hUser32)
		return 0;

	pSendMessageA = (PFNSENDMESSAGEA)GetProcAddress(hUser32, "SendMessageA");
	if (!pSendMessageA)
		return 0;

	return 1;
}

static int rle_decompress(const unsigned char *src, size_t src_len, unsigned char *dst, size_t dst_len) {
	size_t si = 0, di = 0;
	while (si + 1 <= src_len && di < dst_len) {
		unsigned char count = src[si++];
		unsigned char value = src[si++];
		if (count == 0)
			return 0;
		while (count-- && di < dst_len)
			dst[di++] = value;
	}
	return di == dst_len;
}

static unsigned long read_u32_le(const unsigned char *p) {
	return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static int write_file_binary(const char *path, const unsigned char *data, size_t size) {
	FILE *f = fopen(path, "wb");
	if (!f)
		return 0;
	size_t written = fwrite(data, 1, size, f);
	fclose(f);
	return written == size;
}

static void get_program_files_dir(char *buf, size_t bufSize) {
	HKEY hKey;
	LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &hKey);

	if (res == ERROR_SUCCESS) {
		DWORD type = REG_SZ;
		DWORD cb = (DWORD)(bufSize - 1);
		buf[0] = '\0';
		if (RegQueryValueExA(hKey, "ProgramFilesDir", NULL, &type, (LPBYTE)buf, &cb) != ERROR_SUCCESS ||
			type != REG_SZ || !buf[0]) {
			lstrcpynA(buf, "C:\\Program Files", (int)bufSize);
		}
		RegCloseKey(hKey);
	} else {
		lstrcpynA(buf, "C:\\Program Files", (int)bufSize);
	}
}

static void get_default_install_path(char *buf, size_t bufSize) {
	char pf[MAX_PATH];
	get_program_files_dir(pf, sizeof(pf));

	lstrcpynA(buf, pf, (int)bufSize);
	int len = lstrlenA(buf);
	if (len > 0 && buf[len - 1] != '\\') {
		lstrcatA(buf, "\\");
	}
	lstrcatA(buf, PACKAGE_NAME "\\");
}

static void create_dir_recursive(const char *path) {
	char tmp[MAX_PATH];
	lstrcpynA(tmp, path, MAX_PATH);

	char *lastSlash = strrchr(tmp, '\\');
	if (lastSlash && lastSlash != tmp && lastSlash[-1] != ':') {
		*lastSlash = '\0';
	}

	char *p = tmp;

	if (p[0] && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) {
		p += 3;
	}

	for (; *p; ++p) {
		if (*p == '\\' || *p == '/') {
			char ch = *p;
			*p = '\0';
			CreateDirectoryA(tmp, NULL);
			*p = ch;
		}
	}

	CreateDirectoryA(tmp, NULL);
}

static int CALLBACK BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData) {
	if (uMsg == BFFM_INITIALIZED && lpData)
		pSendMessageA(hwnd, BFFM_SETSELECTIONA, TRUE, (LPARAM)lpData);

	return 0;
}

static int choose_install_path(HWND owner, char *pathBuf, size_t bufSize) {
	char initialPath[MAX_PATH];
	lstrcpynA(initialPath, pathBuf, MAX_PATH);

	BROWSEINFOA bi;
	ZeroMemory(&bi, sizeof(bi));
	bi.hwndOwner = owner;
	bi.pidlRoot = NULL;
	bi.pszDisplayName = NULL;
	bi.lpszTitle = "Choose installation folder for " PACKAGE_NAME " package";
	bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
	bi.lpfn = BrowseCallbackProc;
	bi.lParam = (LPARAM)initialPath;

	LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
	if (!pidl)
		return 0;

	char folderBuf[MAX_PATH];
	if (!SHGetPathFromIDListA(pidl, folderBuf) || !folderBuf[0]) {
		CoTaskMemFree(pidl);
		return 0;
	}
	CoTaskMemFree(pidl);

	lstrcpynA(pathBuf, folderBuf, (int)bufSize);

	int len = lstrlenA(pathBuf);
	if (len > 0 && pathBuf[len - 1] != '\\' && pathBuf[len - 1] != '/') {
		if (len + 1 < (int)bufSize) {
			lstrcatA(pathBuf, "\\");
		}
	}

	return 1;
}

static int extract_archive_to(const char *baseDir) {
	const unsigned char *src = installer_archive;
	size_t len = installer_archive_size;
	size_t pos = 0;

	if (len < 8) {
		MessageBoxA(NULL, "Embedded archive is too small", "Installer error", MB_ICONERROR | MB_OK);
		return 0;
	}

	if (src[0] != 'F' || src[1] != 'A' || src[2] != 'R' || src[3] != '0') {
		MessageBoxA(NULL, "Embedded archive has invalid header", "Installer error", MB_ICONERROR | MB_OK);
		return 0;
	}
	pos += 4;

	if (len - pos < 4) {
		MessageBoxA(NULL, "Embedded archive is truncated (no file count)", "Installer error", MB_ICONERROR | MB_OK);
		return 0;
	}

	unsigned long fileCount = read_u32_le(src + pos);
	pos += 4;

	for (unsigned long i = 0; i < fileCount; ++i) {
		if (pos + 12 > len) {
			MessageBoxA(NULL, "Archive truncated while reading file header", "Installer error", MB_ICONERROR | MB_OK);
			return 0;
		}

		unsigned long nameLen = read_u32_le(src + pos);
		pos += 4;
		unsigned long compLen = read_u32_le(src + pos);
		pos += 4;
		unsigned long rawLen = read_u32_le(src + pos);
		pos += 4;

		if ((size_t)nameLen > len - pos) {
			MessageBoxA(NULL, "Archive truncated while reading file name", "Installer error", MB_ICONERROR | MB_OK);
			return 0;
		}

		const char *namePtr = (const char *)(src + pos);
		pos += nameLen;

		if ((size_t)compLen > len - pos) {
			MessageBoxA(NULL, "Archive truncated while reading file data", "Installer error", MB_ICONERROR | MB_OK);
			return 0;
		}

		const unsigned char *compPtr = src + pos;
		pos += compLen;

		if (nameLen == 0)
			continue;

		if (nameLen >= MAX_PATH) {
			MessageBoxA(NULL, "Archive entry path too long", "Installer error", MB_ICONERROR | MB_OK);
			return 0;
		}

		char relPath[MAX_PATH];
		memcpy(relPath, namePtr, nameLen);
		relPath[nameLen] = '\0';

		for (char *p = relPath; *p; ++p) {
			if (*p == '/')
				*p = '\\';
		}

		char fullPath[MAX_PATH];
		lstrcpynA(fullPath, baseDir, MAX_PATH);
		int baseLen = lstrlenA(fullPath);
		if (baseLen > 0 && fullPath[baseLen - 1] != '\\' && fullPath[baseLen - 1] != '/') {
			lstrcatA(fullPath, "\\");
		}
		lstrcatA(fullPath, relPath);

		create_dir_recursive(fullPath);

		unsigned char dummy = 0;
		unsigned char *outBuf = NULL;
		if (rawLen > 0) {
			outBuf = (unsigned char *)malloc(rawLen);
			if (!outBuf) {
				MessageBoxA(NULL, "Out of memory while decompressing file", "Installer error", MB_ICONERROR | MB_OK);
				return 0;
			}
		} else {
			outBuf = &dummy;
		}

		if (!rle_decompress(compPtr, compLen, outBuf, rawLen)) {
			if (rawLen > 0)
				free(outBuf);

			char err[512];
			wsprintfA(err, "Decompression failed for:\n\n%s\n\nThe embedded archive appears to be corrupt.", fullPath);
			MessageBoxA(NULL, err, "Installer error", MB_ICONERROR | MB_OK);
			return 0;
		}

		if (!write_file_binary(fullPath, outBuf, rawLen)) {
			if (rawLen > 0)
				free(outBuf);

			char err[512];
			wsprintfA(err, "Failed to write output file:\n\n%s", fullPath);
			MessageBoxA(NULL, err, "Installer error", MB_ICONERROR | MB_OK);
			return 0;
		}

		if (rawLen > 0)
			free(outBuf);
	}

	return 1;
}

static char *build_archive_file_list(unsigned long *outFileCount) {
	const unsigned char *src = installer_archive;
	size_t len = installer_archive_size;
	size_t pos = 0;

	if (len < 8)
		return NULL;

	if (src[0] != 'F' || src[1] != 'A' || src[2] != 'R' || src[3] != '0')
		return NULL;

	pos += 4;

	if (len - pos < 4)
		return NULL;

	unsigned long fileCount = read_u32_le(src + pos);
	pos += 4;

	size_t pos2 = pos;
	size_t totalLen = 0;

	for (unsigned long i = 0; i < fileCount; ++i) {
		if (pos2 + 12 > len)
			return NULL;

		unsigned long nameLen = read_u32_le(src + pos2);
		pos2 += 4;
		unsigned long compLen = read_u32_le(src + pos2);
		pos2 += 4;
		unsigned long rawLen = read_u32_le(src + pos2);
		(void)rawLen;
		pos2 += 4;

		if ((size_t)nameLen > len - pos2)
			return NULL;

		totalLen += (size_t)nameLen + 4;

		pos2 += nameLen;

		if ((size_t)compLen > len - pos2)
			return NULL;
		pos2 += compLen;
	}

	if (totalLen == 0) {
		if (outFileCount)
			*outFileCount = fileCount;
		char *empty = (char *)malloc(1);
		if (!empty)
			return NULL;
		empty[0] = '\0';
		return empty;
	}

	char *buf = (char *)malloc(totalLen + 1);
	if (!buf)
		return NULL;

	char *dst = buf;
	pos2 = pos;

	for (unsigned long i = 0; i < fileCount; ++i) {
		if (pos2 + 12 > len) {
			free(buf);
			return NULL;
		}

		unsigned long nameLen = read_u32_le(src + pos2);
		pos2 += 4;
		unsigned long compLen = read_u32_le(src + pos2);
		pos2 += 4;
		unsigned long rawLen = read_u32_le(src + pos2);
		(void)rawLen;
		pos2 += 4;

		if ((size_t)nameLen > len - pos2) {
			free(buf);
			return NULL;
		}

		const char *namePtr = (const char *)(src + pos2);
		pos2 += nameLen;

		*dst++ = '-';
		*dst++ = ' ';

		for (unsigned long j = 0; j < nameLen; ++j) {
			char ch = namePtr[j];
			if (ch == '/')
				ch = '\\';
			*dst++ = ch;
		}

		*dst++ = '\r';
		*dst++ = '\n';

		if ((size_t)compLen > len - pos2) {
			free(buf);
			return NULL;
		}
		pos2 += compLen;
	}

	*dst = '\0';

	if (outFileCount)
		*outFileCount = fileCount;

	return buf;
}

int main(void) {
	char installPath[MAX_PATH];
	bool allowCustomInstallPath = false;

	get_default_install_path(installPath, sizeof(installPath));

	if (!ensure_SendMessageA_loaded())
		MessageBoxA(NULL, "SendMessageA could not be localized, custom install path disabled.", "Installer warning",
					MB_ICONWARNING | MB_OK);
	else
		allowCustomInstallPath = true;

	unsigned long fileCount = 0;
	char *fileList = build_archive_file_list(&fileCount);
	if (!fileList) {
		MessageBoxA(NULL, "Embedded archive is invalid or could not be enumerated.", "Installer error",
					MB_ICONERROR | MB_OK);
		return 1;
	}

	size_t listLen = lstrlenA(fileList);
	size_t pathLen = lstrlenA(installPath);
	size_t msgSize = listLen + pathLen + 1024;

	char *msg = (char *)malloc(msgSize);
	if (!msg) {
		free(fileList);
		MessageBoxA(NULL, "Out of memory while preparing the installation dialog.", "Installer error",
					MB_ICONERROR | MB_OK);
		return 1;
	}

	msg[0] = '\0';

	char tmp[512];

	wsprintfA(tmp, "This installer will extract %lu files.\r\n\r\n", fileCount);
	lstrcatA(msg, tmp);

	lstrcatA(msg, "Default installation location:\r\n");
	lstrcatA(msg, installPath);
	lstrcatA(msg, "\r\n\r\n");

	lstrcatA(msg, "Files to be installed:\r\n\r\n");
	lstrcatA(msg, fileList);

	lstrcatA(msg, "\r\n");
	lstrcatA(msg, "Yes = install package here\r\n");
	lstrcatA(msg, "No  = choose a different location\r\n");
	lstrcatA(msg, "Cancel = abort.");

	int r = MessageBoxA(NULL, msg, PACKAGE_NAME " installer", MB_ICONQUESTION | MB_YESNOCANCEL);

	free(msg);
	free(fileList);

	if (r == IDCANCEL) {
		return 0;
	}

	if (r == IDNO) {
		if (allowCustomInstallPath) {
			if (!choose_install_path(NULL, installPath, sizeof(installPath))) {
				return 0;
			}
		} else {
			MessageBoxA(NULL, "Custom install path is unavailable.", "Installer error", MB_ICONERROR | MB_OK);
			return 1;
		}
	}

	if (!extract_archive_to(installPath)) {
		return 1;
	}

	char doneMsg[512];
	wsprintfA(doneMsg, PACKAGE_NAME " package (multiple files) installed to:\n\n%s", installPath);

	MessageBoxA(NULL, doneMsg, "Installation complete", MB_ICONINFORMATION | MB_OK);

	return 0;
}
