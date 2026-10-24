#include <windows.h>
#include <sddl.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "filelog.h"

#define LOG_MAX_BYTES	(1024 * 1024)
#define LOG_KEEP	3	/* service.1.log .. service.3.log */

/* SYSTEM 과 관리자는 모두, 사용자는 읽기만. P 는 위 폴더(ProgramData)의 권한을 물려받지 않는다는 뜻 —
 * ProgramData 는 사용자에게 파일을 만들 권한을 주므로 물려받으면 누구나 로그를 바꿔 놓을 수 있다. */
#define DIR_SDDL L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

static CRITICAL_SECTION lock;
static int lock_ready;
static HANDLE file = INVALID_HANDLE_VALUE;
static wchar_t log_dir[MAX_PATH];
static wchar_t dump_dir[MAX_PATH];
static wchar_t log_path[MAX_PATH];

static void make_dir(const wchar_t *path)
{
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(DIR_SDDL, SDDL_REVISION_1, &sd, NULL)) {
		sa.lpSecurityDescriptor = sd;
	}
	CreateDirectoryW(path, sd != NULL ? &sa : NULL);
	if (sd != NULL) {
		LocalFree(sd);
	}
}

static void open_file(void)
{
	file = CreateFileW(log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

/* service.log -> service.1.log -> ... service.LOG_KEEP.log (가장 오래된 것은 지운다). */
static void rotate(void)
{
	wchar_t from[MAX_PATH], to[MAX_PATH];
	int i;

	CloseHandle(file);
	file = INVALID_HANDLE_VALUE;

	swprintf(to, MAX_PATH, L"%ls\\service.%d.log", log_dir, LOG_KEEP);
	DeleteFileW(to);
	for (i = LOG_KEEP - 1; i >= 1; i--) {
		swprintf(from, MAX_PATH, L"%ls\\service.%d.log", log_dir, i);
		swprintf(to, MAX_PATH, L"%ls\\service.%d.log", log_dir, i + 1);
		MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING);
	}
	swprintf(to, MAX_PATH, L"%ls\\service.1.log", log_dir);
	MoveFileExW(log_path, to, MOVEFILE_REPLACE_EXISTING);

	open_file();
}

void filelog_open(void)
{
	wchar_t base[MAX_PATH];

	if (!lock_ready) {
		InitializeCriticalSection(&lock);
		lock_ready = 1;
	}
	if (!ExpandEnvironmentStringsW(L"%ProgramData%\\ztgate", base, MAX_PATH)) {
		return;
	}
	make_dir(base);
	swprintf(log_dir, MAX_PATH, L"%ls\\logs", base);
	swprintf(dump_dir, MAX_PATH, L"%ls\\dumps", base);
	make_dir(log_dir);
	make_dir(dump_dir);
	swprintf(log_path, MAX_PATH, L"%ls\\service.log", log_dir);

	EnterCriticalSection(&lock);
	open_file();
	LeaveCriticalSection(&lock);
}

void filelog_write(const char *line)
{
	char buf[1024];
	SYSTEMTIME st;
	LARGE_INTEGER size;
	DWORD n;
	int len;

	if (!lock_ready) {
		return;
	}

	/* 시각은 UTC 로 적는다. 서버의 로그(journald)와 맞춰 볼 때 시간대를 따지지 않아도 된다. */
	GetSystemTime(&st);
	len = snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ %s\r\n",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, line);
	if (len < 0) {
		return;
	}
	if (len >= (int)sizeof(buf)) {
		len = (int)sizeof(buf) - 1;
		buf[len - 2] = '\r';
		buf[len - 1] = '\n';
	}

	EnterCriticalSection(&lock);
	if (file != INVALID_HANDLE_VALUE) {
		WriteFile(file, buf, (DWORD)len, &n, NULL);
		if (GetFileSizeEx(file, &size) && size.QuadPart > LOG_MAX_BYTES) {
			rotate();
		}
	}
	LeaveCriticalSection(&lock);
}

void filelog_close(void)
{
	if (!lock_ready) {
		return;
	}
	EnterCriticalSection(&lock);
	if (file != INVALID_HANDLE_VALUE) {
		CloseHandle(file);
		file = INVALID_HANDLE_VALUE;
	}
	LeaveCriticalSection(&lock);
}

/* ---- 덤프 ---------------------------------------------------------------------- */
typedef BOOL (WINAPI *minidump_fn)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

static LONG WINAPI on_crash(EXCEPTION_POINTERS *info)
{
	wchar_t path[MAX_PATH];
	MINIDUMP_EXCEPTION_INFORMATION mei;
	SYSTEMTIME st;
	minidump_fn dump;
	HMODULE dbghelp;
	HANDLE f;

	/* 무너지는 중이라 할 수 있는 일만 한다: 덤프 파일 하나. dbghelp 는 System32 에서만 찾는다. */
	if (dump_dir[0] == L'\0') {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	dbghelp = LoadLibraryExW(L"dbghelp.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (dbghelp == NULL) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	dump = (minidump_fn)(void (*)(void))GetProcAddress(dbghelp, "MiniDumpWriteDump");
	if (dump == NULL) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	GetSystemTime(&st);
	swprintf(path, MAX_PATH, L"%ls\\vpn_service-%04u%02u%02uT%02u%02u%02uZ-%lu.dmp", dump_dir,
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId());
	f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	mei.ThreadId = GetCurrentThreadId();
	mei.ExceptionPointers = info;
	mei.ClientPointers = FALSE;
	/* 스레드와 스택만 (MiniDumpNormal). 힙 전체를 담으면 세션 키와 토큰까지 파일에 남는다. */
	dump(GetCurrentProcess(), GetCurrentProcessId(), f, MiniDumpNormal, &mei, NULL, NULL);
	CloseHandle(f);

	return EXCEPTION_CONTINUE_SEARCH;
}

void filelog_install_crash_handler(void)
{
	SetUnhandledExceptionFilter(on_crash);
}
