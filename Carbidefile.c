#include <Carbide/Recipe.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *tool_prefix(void) {
	const char *p = getenv("TOOL_PREFIX");

	return p && *p ? p : "i686-w64-mingw32-";
}

static const char *gcc_path(void) {
	static char buf[256];
	snprintf(buf, sizeof(buf), "%sgcc", tool_prefix());
	return buf;
}

static const char *dlltool_path(void) {
	static char buf[256];
	snprintf(buf, sizeof(buf), "%sdlltool", tool_prefix());
	return buf;
}

static const char *default_exe_name(void) {
	const char *n = getenv("CB_EXE_NAME");
	return (n && *n) ? n : "app";
}

static const char *default_dll_name(void) {
	const char *n = getenv("CB_DLL_NAME");
	return (n && *n) ? n : "mylib";
}

static const char *locate_def_dir(void) {
	const char *env = getenv("WIN95_GENERATED_PATH");
	if (env && *env && cb_is_dir(env)) {
		return cb_norm(env);
	}

	cb_log_error("Could not locate .def directory. Set WIN95_GENERATED_PATH");
	return CB_NULL;
}

static const char *ensure_out_libdir(void) {
	const char *libdir = cb_join(cb_out_root(), "lib/win95");
	return cb_mkdir_p(libdir);
}

static const char *ensure_out_bindir(void) {
	const char *bindir = cb_join(cb_out_root(), "bin");
	return cb_mkdir_p(bindir);
}

typedef struct {
	char *name;
	size_t name_len;
	unsigned char *rle_data;
	size_t rle_len;
	size_t raw_len;
} packed_file;

static int rle_compress_buffer(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len) {
	unsigned char *tmp = malloc(in_len * 2 + 2);
	if (!tmp) {
		return -1;
	}

	size_t oi = 0;
	size_t i = 0;
	while (i < in_len) {
		unsigned char v = in[i];
		size_t run = 1;
		while (i + run < in_len && in[i + run] == v && run < 255) {
			run++;
		}
		tmp[oi++] = (unsigned char)run;
		tmp[oi++] = v;
		i += run;
	}

	*out = tmp;
	*out_len = oi;
	return 0;
}

static void emit_byte(FILE *f, unsigned char b, size_t *col) {
	fprintf(f, "0x%02X,", (unsigned)b);
	if (++(*col) == 12) {
		fprintf(f, "\n    ");
		*col = 0;
	}
}

static void emit_u32_le(FILE *f, unsigned long v, size_t *col) {
	emit_byte(f, (unsigned char)(v & 0xFF), col);
	emit_byte(f, (unsigned char)((v >> 8) & 0xFF), col);
	emit_byte(f, (unsigned char)((v >> 16) & 0xFF), col);
	emit_byte(f, (unsigned char)((v >> 24) & 0xFF), col);
}

static char *make_archive_name(const char *dist_root, const char *path) {
	const char *rel = path;
	size_t root_len = strlen(dist_root);

	if (strncmp(path, dist_root, root_len) == 0) {
		rel = path + root_len;
		if (*rel == '/' || *rel == '\\')
			++rel;
	}

	size_t len = strlen(rel);
	char *name = (char *)malloc(len + 1);
	if (!name)
		return CB_NULL;

	memcpy(name, rel, len + 1);

	for (char *p = name; *p; ++p) {
		if (*p == '\\')
			*p = '/';
	}

	return name;
}

static int write_archive_c(const char *dst_c, const packed_file *files, size_t file_count, size_t archive_len) {
	FILE *f = fopen(dst_c, "wb");
	if (!f) {
		cb_log_error("Failed to open %s for writing", dst_c);
		return -1;
	}

	fprintf(f, "#include <stddef.h>\n\n");
	fprintf(f, "const unsigned char installer_archive[] = {\n    ");

	size_t col = 0;

	emit_byte(f, 'F', &col);
	emit_byte(f, 'A', &col);
	emit_byte(f, 'R', &col);
	emit_byte(f, '0', &col);

	emit_u32_le(f, (unsigned long)file_count, &col);

	for (size_t i = 0; i < file_count; ++i) {
		const packed_file *pf = &files[i];

		emit_u32_le(f, (unsigned long)pf->name_len, &col);
		emit_u32_le(f, (unsigned long)pf->rle_len, &col);
		emit_u32_le(f, (unsigned long)pf->raw_len, &col);

		for (size_t j = 0; j < pf->name_len; ++j) {
			emit_byte(f, (unsigned char)pf->name[j], &col);
		}

		for (size_t j = 0; j < pf->rle_len; ++j) {
			emit_byte(f, pf->rle_data[j], &col);
		}
	}

	fprintf(f, "\n};\n\n");
	fprintf(f, "const size_t installer_archive_size = %zu;\n", archive_len);

	fclose(f);

	if (cb_is_verbose())
		cb_log_info("Wrote archive C blob %s", cb_rel_to_workspace(dst_c));

	return 0;
}

static const char *ensure_archive_c(void) {
	const char *dist_root = cb_join(cb_workspace_root(), "dist");
	if (!cb_is_dir(dist_root)) {
		cb_log_error("dist directory not found: %s", cb_rel_to_workspace(dist_root));
		return CB_NULL;
	}

	cb_strlist paths;
	cb_strlist_init(&paths);

	cb_rglob(dist_root, CB_NULL, &paths);

	if (paths.len == 0) {
		cb_log_error("No files to pack in %s", cb_rel_to_workspace(dist_root));
		cb_strlist_free(&paths);
		return CB_NULL;
	}

	const char *gendir = cb_join(cb_out_root(), "generated");
	if (!cb_mkdir_p(gendir)) {
		cb_strlist_free(&paths);
		return CB_NULL;
	}

	const char *dst = cb_join(gendir, "fasmg_archive.c");

	const char **inputs = (const char **)paths.data;
	if (!cb_needs_rebuild(dst, inputs, paths.len)) {
		if (cb_is_verbose())
			cb_log_verbose("Up to date: %s", cb_rel_to_workspace(dst));
		cb_strlist_free(&paths);
		return dst;
	}

	size_t file_count = paths.len;
	packed_file *files = (packed_file *)calloc(file_count, sizeof(packed_file));
	if (!files) {
		cb_log_error("Out of memory preparing archive");
		cb_strlist_free(&paths);
		return CB_NULL;
	}

	int failed = 0;

	for (size_t i = 0; i < file_count; ++i) {
		const char *path = paths.data[i];

		FILE *in = fopen(path, "rb");
		if (!in) {
			cb_log_error("Failed to open %s", cb_rel_to_workspace(path));
			failed = 1;
			break;
		}

		if (fseek(in, 0, SEEK_END) != 0) {
			cb_log_error("fseek failed on %s", cb_rel_to_workspace(path));
			fclose(in);
			failed = 1;
			break;
		}

		long len = ftell(in);
		if (len < 0) {
			cb_log_error("ftell failed on %s", cb_rel_to_workspace(path));
			fclose(in);
			failed = 1;
			break;
		}
		rewind(in);

		unsigned char *buf = (unsigned char *)malloc((size_t)len);
		if (!buf) {
			cb_log_error("Out of memory reading %s", cb_rel_to_workspace(path));
			fclose(in);
			failed = 1;
			break;
		}

		size_t read = fread(buf, 1, (size_t)len, in);
		fclose(in);
		if (read != (size_t)len) {
			cb_log_error("Short read on %s", cb_rel_to_workspace(path));
			free(buf);
			failed = 1;
			break;
		}

		unsigned char *rle_data = NULL;
		size_t rle_len = 0;
		if (rle_compress_buffer(buf, (size_t)len, &rle_data, &rle_len) != 0) {
			cb_log_error("Out of memory while compressing %s", cb_rel_to_workspace(path));
			free(buf);
			failed = 1;
			break;
		}
		free(buf);

		char *name = make_archive_name(dist_root, path);
		if (!name) {
			cb_log_error("Out of memory building archive name for %s", cb_rel_to_workspace(path));
			free(rle_data);
			failed = 1;
			break;
		}

		files[i].name = name;
		files[i].name_len = strlen(name);
		files[i].rle_data = rle_data;
		files[i].rle_len = rle_len;
		files[i].raw_len = (size_t)len;
	}

	size_t archive_len = 0;
	if (!failed) {
		archive_len = 4 + 4;
		for (size_t i = 0; i < file_count; ++i) {
			archive_len += 4 + 4 + 4;
			archive_len += files[i].name_len;
			archive_len += files[i].rle_len;
		}

		if (write_archive_c(dst, files, file_count, archive_len) != 0) {
			failed = 1;
		}
	}

	for (size_t i = 0; i < file_count; ++i) {
		free(files[i].name);
		free(files[i].rle_data);
	}
	free(files);

	cb_strlist_free(&paths);

	if (failed)
		return CB_NULL;

	return dst;
}

static void lowercase(char *s) {
	for (; *s; ++s)
		*s = (char)tolower((unsigned char)*s);
}

static void basename_no_ext(const char *path, char *out, size_t outsz) {
	const char *b = strrchr(path, '/');
#ifdef _WIN32
	if (!b)
		b = strrchr(path, '\\');
#endif
	b = b ? b + 1 : path;
	const char *dot = strrchr(b, '.');
	size_t n = dot ? (dot - b) : strlen(b);
	if (n >= outsz)
		n = outsz - 1;
	memcpy(out, b, n);
	out[n] = '\0';
}

static void make_importlib_name(const char *def_path, char *out, size_t outsz) {
	char base[192];
	basename_no_ext(def_path, base, sizeof(base));
	lowercase(base);
	snprintf(out, outsz, "lib%s.a", base);
}

static int dlltool_from_def(const char *def_path, const char *out_a) {
	cb_cmd *c = cb_cmd_new();
	cb_cmd_push_arg(c, dlltool_path());
	cb_cmd_push_arg(c, "-d");
	cb_cmd_push_arg(c, def_path);

	cb_cmd_push_arg(c, "-k");
	cb_cmd_push_arg(c, "-l");
	cb_cmd_push_arg(c, out_a);
	int code = 0;
	int rc = cb_cmd_run(c, &code);
	cb_cmd_free(c);

	if (rc != 0 || code != 0) {
		cb_log_error("dlltool failed for %s -> %s (rc=%d, code=%d)", def_path, out_a, rc, code);
		return -1;
	}

	if (cb_is_verbose())
		cb_log_info("Generated %s", cb_rel_to_workspace(out_a));

	return 0;
}

static const char *ensure_import_libs(void) {
	const char *def_dir = locate_def_dir();
	if (!def_dir)
		return CB_NULL;

	const char *libdir = ensure_out_libdir();
	cb_strlist defs;
	cb_strlist_init(&defs);
	cb_glob(cb_join(def_dir, "*.def"), &defs);

	if (defs.len == 0) {
		cb_log_error("No .def files found in %s", def_dir);
		cb_strlist_free(&defs);
		return CB_NULL;
	}

	for (size_t i = 0; i < defs.len; ++i) {
		const char *defp = defs.data[i];
		char libname[256];
		make_importlib_name(defp, libname, sizeof(libname));
		const char *out_a = cb_join(libdir, libname);

		const char *inputs[1] = {defp};
		if (cb_needs_rebuild(out_a, inputs, 1)) {
			if (dlltool_from_def(defp, out_a) != 0) {
				cb_strlist_free(&defs);
				return CB_NULL;
			}
		} else if (cb_is_verbose()) {
			cb_log_verbose("Up to date: %s", cb_rel_to_workspace(out_a));
		}
	}

	cb_strlist_free(&defs);
	return libdir;
}

static void collect_exe_sources(cb_strlist *out) {
	const char *root = cb_join(cb_workspace_root(), "source/exe");
	if (!cb_is_dir(root)) {
		cb_log_error("EXE source directory not found: %s", cb_rel_to_workspace(root));
		return;
	}
	cb_rglob(root, ".c", out);
}

static void collect_dll_sources(cb_strlist *out) {
	const char *root = cb_join(cb_workspace_root(), "source/dll");
	if (!cb_is_dir(root)) {
		cb_log_error("DLL source directory not found: %s", cb_rel_to_workspace(root));
		return;
	}
	cb_rglob(root, ".c", out);
}

static void push_sources_to_cmd(cb_cmd *c, const cb_strlist *srcs) {
	for (size_t i = 0; i < srcs->len; ++i) {
		cb_cmd_push_arg(c, srcs->data[i]);
	}
}

static const char *exe_crt0_path(void) {
	const char *p = cb_join(cb_workspace_root(), "crt/w95_crt0_exe.c");
	return cb_file_exists(p) ? p : CB_NULL;
}
static const char *dll_crt0_path(void) {
	const char *p = cb_join(cb_workspace_root(), "crt/w95_crt0_dll.c");
	return cb_file_exists(p) ? p : CB_NULL;
}

static int cmd_exe(void) {
	const char *libdir = ensure_import_libs();
	if (!libdir)
		return 1;

	const char *bindir = ensure_out_bindir();
	const char *exe_name = default_exe_name();

	const char *archive_c = ensure_archive_c();
	if (!archive_c)
		return 1;

	cb_strlist srcs;
	cb_strlist_init(&srcs);
	collect_exe_sources(&srcs);
	if (srcs.len == 0) {
		cb_log_error("No EXE sources found (expected under source/exe/**/*.c)");
		cb_strlist_free(&srcs);
		return 1;
	}

	const char *out_exe = cb_join(bindir, cb_join("", exe_name));
	char outbuf[512];
	snprintf(outbuf, sizeof(outbuf), "%s.exe", out_exe);

	const char *crt0 = exe_crt0_path();
	if (!crt0) {
		cb_log_error("Missing crt/w95_crt0_exe.c");
		return 1;
	}

	cb_cmd *c = cb_cmd_new();
	cb_cmd_push_arg(c, gcc_path());
	cb_cmd_push_arg(c, "-nostartfiles");
	cb_cmd_push_arg(c, "-nostdlib");

	cb_cmd_push_arg(c, "-O2");
	cb_cmd_push_arg(c, "-s");
	cb_cmd_push_arg(c, "-fno-asynchronous-unwind-tables");
	cb_cmd_push_arg(c, "-fno-ident");
	cb_cmd_push_arg(c, "-march=pentium");
	cb_cmd_push_arg(c, "-mno-sse");
	cb_cmd_push_arg(c, "-mno-sse2");
	cb_cmd_push_arg(c, "-o");
	cb_cmd_push_arg(c, outbuf);

	cb_cmd_push_arg(c, crt0);
	push_sources_to_cmd(c, &srcs);

	cb_cmd_push_arg(c, archive_c);

	cb_cmd_push_arg(c, "-L");
	cb_cmd_push_arg(c, libdir);

	cb_cmd_push_arg(c, "-Wl,--subsystem,windows");
	cb_cmd_push_arg(c, "-Wl,--major-subsystem-version,4");
	cb_cmd_push_arg(c, "-Wl,--minor-subsystem-version,0");
	cb_cmd_push_arg(c, "-Wl,-e,_mainCRTStartup@0");

	cb_cmd_push_arg(c, "-lkernel32");
	cb_cmd_push_arg(c, "-lmsvcrt");
	cb_cmd_push_arg(c, "-lgcc");

	const char *extra = getenv("EXTRA_LIBS");
	if (extra && *extra) {
		char tmp[512];
		strncpy(tmp, extra, sizeof(tmp) - 1);
		tmp[sizeof(tmp) - 1] = 0;
		char *tok = strtok(tmp, " ");
		while (tok) {
			char flag[64];
			snprintf(flag, sizeof(flag), "-l%s", tok);
			cb_cmd_push_arg(c, flag);
			tok = strtok(NULL, " ");
		}
	}

	int code = 0;
	int rc = cb_cmd_run(c, &code);
	cb_cmd_free(c);

	if (rc != 0 || code != 0) {
		cb_log_error("link failed (rc=%d, code=%d)", rc, code);
		return 1;
	}
	cb_log_verbose("Built %s", cb_rel_to_workspace(outbuf));
	return 0;
}

static int cmd_dll(void) {
	const char *libdir = ensure_import_libs();
	if (!libdir)
		return 1;

	const char *bindir = ensure_out_bindir();
	const char *dll_base = default_dll_name();

	cb_strlist srcs;
	cb_strlist_init(&srcs);
	collect_dll_sources(&srcs);
	if (srcs.len == 0) {
		cb_log_error("No DLL sources found (expected under source/dll/**/*.c)");
		cb_strlist_free(&srcs);
		return 1;
	}

	char outdll[512];
	snprintf(outdll, sizeof(outdll), "%s.dll", cb_join(bindir, cb_join("", dll_base)));

	const char *crt0 = dll_crt0_path();
	if (!crt0) {
		cb_log_error("Missing crt/w95_crt0_dll.c");
		return 1;
	}
	cb_cmd *c = cb_cmd_new();
	cb_cmd_push_arg(c, gcc_path());
	cb_cmd_push_arg(c, "-shared");

	cb_cmd_push_arg(c, "-nostartfiles");
	cb_cmd_push_arg(c, "-nostdlib");

	cb_cmd_push_arg(c, "-O2");
	cb_cmd_push_arg(c, "-s");
	cb_cmd_push_arg(c, "-fno-asynchronous-unwind-tables");
	cb_cmd_push_arg(c, "-fno-ident");
	cb_cmd_push_arg(c, "-march=pentium");
	cb_cmd_push_arg(c, "-mno-sse");
	cb_cmd_push_arg(c, "-mno-sse2");
	cb_cmd_push_arg(c, "-o");
	cb_cmd_push_arg(c, outdll);

	cb_cmd_push_arg(c, crt0);
	push_sources_to_cmd(c, &srcs);

	cb_cmd_push_arg(c, "-L");
	cb_cmd_push_arg(c, libdir);

	cb_cmd_push_arg(c, "-Wl,--major-subsystem-version,4");
	cb_cmd_push_arg(c, "-Wl,--minor-subsystem-version,0");
	cb_cmd_push_arg(c, "-Wl,-e,_DllMainCRTStartup@12");

	cb_cmd_push_arg(c, "-lkernel32");
	cb_cmd_push_arg(c, "-lmsvcrt");
	cb_cmd_push_arg(c, "-lgcc");

	const char *extra = getenv("EXTRA_LIBS");
	if (extra && *extra) {
		char tmp[512];
		strncpy(tmp, extra, sizeof(tmp) - 1);
		tmp[sizeof(tmp) - 1] = 0;
		char *tok = strtok(tmp, " ");
		while (tok) {
			char flag[64];
			snprintf(flag, sizeof(flag), "-l%s", tok);
			cb_cmd_push_arg(c, flag);
			tok = strtok(NULL, " ");
		}
	}

	int code = 0;
	int rc = cb_cmd_run(c, &code);
	cb_cmd_free(c);

	if (rc != 0 || code != 0) {
		cb_log_error("dll link failed (rc=%d, code=%d)", rc, code);
		return 1;
	}
	cb_log_verbose("Built %s", cb_rel_to_workspace(outdll));
	return 0;
}

static int cmd_default(void) {
	cb_log_info("Usage:");
	cb_log_info("  carbide exe");
	cb_log_info("  carbide dll");
	cb_log_info("");

	cb_log_info("Env:");
	cb_log_info("  WIN95_GENERATED_PATH=<path-to-defs>");
	cb_log_info("  TOOL_PREFIX=i686-w64-mingw32- (default)");
	cb_log_info("  EXTRA_LIBS=\"user32 gdi32 wsock32 winmm comdlg32 advapi32 "
				"shell32 ole32 oleaut32\"");
	return 0;
}

int carbide_recipe_main(void) {
	cb_register_cmd("exe", cmd_exe, "Build a Win95-compatible windowed EXE");
	cb_register_cmd("dll", cmd_dll, "Build a Win95-compatible DLL");

	cb_set_default(cmd_default, "Show help");
	return 0;
}
