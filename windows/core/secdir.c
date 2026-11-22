#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

#include "secdir.h"

/* 사용자가 만든 폴더는 DACL 에서 SYSTEM 을 뺐을 수 있다. SeRestorePrivilege 가 켜져 있으면
 * FILE_FLAG_BACKUP_SEMANTICS 로 여는 쪽은 DACL 과 상관없이 WRITE_DAC / WRITE_OWNER 를 받는다. SYSTEM 의
 * 토큰에는 이 권한이 있지만 꺼져 있을 수 있어 켠다. 없으면(관리자가 아닌 프로세스) 그냥 실패한다. */
static void enable_restore(void)
{
	TOKEN_PRIVILEGES tp;
	HANDLE tok;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tok)) {
		return;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (LookupPrivilegeValueW(NULL, SE_RESTORE_NAME, &tp.Privileges[0].Luid)) {
		AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
	}
	CloseHandle(tok);
}

/* 재분석 지점을 따라가지 않고 그 이름 자체를 연다. */
static HANDLE open_dir(const wchar_t *path, DWORD *attrs)
{
	BY_HANDLE_FILE_INFORMATION fi;
	HANDLE h;

	h = CreateFileW(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return h;
	}
	if (!GetFileInformationByHandle(h, &fi)) {
		CloseHandle(h);
		return INVALID_HANDLE_VALUE;
	}
	*attrs = fi.dwFileAttributes;
	return h;
}

int secdir_make(const wchar_t *path, const wchar_t *sddl)
{
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
	PSID owner = NULL;
	PACL dacl = NULL;
	BOOL present = FALSE, defaulted = FALSE;
	DWORD attrs = 0;
	HANDLE h;
	int ret = -1;

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
		return -1;
	}
	if (!GetSecurityDescriptorOwner(sa.lpSecurityDescriptor, &owner, &defaulted) || !owner ||
			!GetSecurityDescriptorDacl(sa.lpSecurityDescriptor, &present, &dacl, &defaulted) || !present) {
		goto out;
	}

	enable_restore();
	CreateDirectoryW(path, &sa);
	h = open_dir(path, &attrs);
	if (h != INVALID_HANDLE_VALUE && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
		/* 누가 둔 링크다. RemoveDirectoryW 는 링크만 지우고 가리키던 곳은 건드리지 않는다. */
		CloseHandle(h);
		h = INVALID_HANDLE_VALUE;
		if (RemoveDirectoryW(path) && CreateDirectoryW(path, &sa)) {
			h = open_dir(path, &attrs);
		}
	}
	if (h == INVALID_HANDLE_VALUE) {
		goto out;
	}
	if ((attrs & FILE_ATTRIBUTE_DIRECTORY) && !(attrs & FILE_ATTRIBUTE_REPARSE_POINT) &&
			SetSecurityInfo(h, SE_FILE_OBJECT,
				OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				owner, NULL, dacl, NULL) == ERROR_SUCCESS) {
		ret = 0;
	}
	CloseHandle(h);

out:
	LocalFree(sa.lpSecurityDescriptor);
	return ret;
}
