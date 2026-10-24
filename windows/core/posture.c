#include <windows.h>
#include <objbase.h>
#include <netfw.h>
#include <wscapi.h>
#include <wbemidl.h>
#include <shobjidl.h>
#include <propsys.h>
#include <propvarutil.h>
#include <string.h>
#include <wchar.h>

#include "posture.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")

/* ---- OS version ---------------------------------------------------------- */
/* GetVersionExW 는 쓸 수 없다. Windows 8.1 부터 실행 파일의 매니페스트에 적힌
 * 호환성 선언을 보고 값을 돌려주므로, 선언이 없으면 Windows 11 에서도 6.2
 * (Windows 8)라고 답한다. 포스처는 프로그램이 "어떤 OS 로 취급받는가"가 아니라
 * 실제로 깔린 OS 를 보고해야 하므로, 그 보정을 거치지 않는 ntdll 의
 * RtlGetVersion 을 부른다.
 *
 * ntdll.dll 은 모든 프로세스에 이미 올라와 있어 LoadLibrary 가 아니라
 * GetModuleHandle 로 얻는다. 참조 횟수를 올리지 않으므로 FreeLibrary 도 없다. */
typedef LONG (WINAPI *rtl_get_version_fn)(RTL_OSVERSIONINFOW *info);

static void collect_os(posture_t *out)
{
	RTL_OSVERSIONINFOW info;
	rtl_get_version_fn rtl_get_version;
	HMODULE ntdll;

	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		return;
	}

	rtl_get_version = (rtl_get_version_fn)GetProcAddress(ntdll, "RtlGetVersion");
	if (!rtl_get_version) {
		return;
	}

	memset(&info, 0, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);
	if (rtl_get_version(&info) != 0) { /* STATUS_SUCCESS == 0 */
		return;
	}

	out->os_major = info.dwMajorVersion;
	out->os_minor = info.dwMinorVersion;
	out->os_build = info.dwBuildNumber;
}

/* ---- firewall ------------------------------------------------------------ */
/* Windows 방화벽 설정은 COM 인터페이스 INetFwPolicy2 로 읽는다. 레지스트리를 직접
 * 읽는 방법도 있지만 그룹 정책이 덮어쓴 값은 다른 키에 있어서, 둘을 합친 "실제로
 * 적용되는 값"은 이 인터페이스가 계산해 준다.
 *
 * 방화벽은 프로필(도메인 / 개인 / 공용)마다 따로 켜고 끈다. 지금 연결된 네트워크에
 * 걸린 프로필만 의미가 있으므로 get_CurrentProfileTypes 로 활성 프로필을 얻고,
 * 그중 하나라도 꺼져 있으면 OFF 로 본다. 네트워크가 여러 개면 프로필도 여러 개가
 * 동시에 활성일 수 있어 비트마스크로 온다.
 *
 * C 에서는 COM 메서드를 obj->lpVtbl->Method(obj, ...) 로 부른다. C++ 의
 * obj->Method(...) 가 실제로 하는 일(가상 함수 테이블에서 함수 포인터를 꺼내
 * this 를 첫 인자로 넘김)을 손으로 쓰는 것이다. */
static uint8_t collect_firewall(void)
{
	static const NET_FW_PROFILE_TYPE2 PROFILES[] = {
		NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC
	};
	INetFwPolicy2 *policy = NULL;
	uint8_t state = POSTURE_UNKNOWN;
	long active = 0;
	HRESULT init;
	HRESULT hr;
	size_t i;

	/* 호출한 스레드가 COM 을 이미 초기화했을 수 있다.
	 *   S_OK / S_FALSE      우리 호출이 참조를 하나 올렸으므로 CoUninitialize 로 짝을 맞춘다.
	 *   RPC_E_CHANGED_MODE  다른 모드로 이미 초기화돼 있다. 그대로 쓸 수 있고, 우리가
	 *                       올린 참조가 없으니 CoUninitialize 를 부르면 안 된다. */
	init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(init) && init != RPC_E_CHANGED_MODE) {
		return POSTURE_UNKNOWN;
	}

	hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
			&IID_INetFwPolicy2, (void **)&policy);
	if (FAILED(hr)) {
		goto out;
	}

	hr = policy->lpVtbl->get_CurrentProfileTypes(policy, &active);
	if (FAILED(hr) || active == 0) {
		goto out;
	}

	state = POSTURE_ON;
	for (i = 0; i < sizeof(PROFILES) / sizeof(PROFILES[0]); i++) {
		VARIANT_BOOL enabled = VARIANT_FALSE;

		if (!(active & PROFILES[i])) {
			continue;
		}

		hr = policy->lpVtbl->get_FirewallEnabled(policy, PROFILES[i], &enabled);
		if (FAILED(hr)) {
			state = POSTURE_UNKNOWN;
			break;
		}
		if (enabled == VARIANT_FALSE) {
			state = POSTURE_OFF;
			break;
		}
	}

out:
	if (policy) {
		policy->lpVtbl->Release(policy);
	}
	if (SUCCEEDED(init)) {
		CoUninitialize();
	}

	return state;
}

/* ---- antivirus ----------------------------------------------------------- */
/* 백신은 제품마다 상태를 읽는 방법이 다르다. 제품별 코드를 두는 대신 Windows 보안
 * 센터(WSC)에 묻는다. 백신은 설치될 때 WSC 에 자신을 등록하고 실시간 감시 여부와
 * 정의 파일이 최신인지를 계속 보고하므로, WSC 한 곳만 보면 Defender 든 서드파티든
 * 같은 답을 얻는다.
 *
 * 방화벽도 WSC 로 물을 수 있지만 그쪽은 INetFwPolicy2 를 썼다. WSC 는 정상 / 불량
 * 한 값만 주고, 어느 프로필이 꺼졌는지와 그 프로필이 지금 쓰이는지는 알려주지 않는다.
 *
 * WSC 는 클라이언트 Windows 에만 있다. 서비스가 없거나 멈춰 있으면 S_FALSE 가
 * 오고 health 는 믿을 수 없으므로 UNKNOWN 으로 둔다.
 *
 * Windows Server 에는 wscapi.dll 자체가 없다. 그래서 이 함수를 import 표로 묶지 않고
 * 부를 때 찾는다. import 로 묶으면 로더가 프로세스를 띄우기도 전에 "DLL 을 찾을 수
 * 없음"(0xC0000135)으로 끝내 버려, 백신과 아무 상관 없는 selftest 조차 돌지 않는다.
 * 없으면 UNKNOWN 이고, UNKNOWN 은 서버에서 통과가 아니다 — 백신을 요구하는 정책은
 * 그대로 거절한다. 읽을 수 없다는 것을 "문제없음"으로 바꿔 말하지 않는다.
 *
 * LOAD_LIBRARY_SEARCH_SYSTEM32 로 System32 에서만 찾는다. 이름만 주면 실행 파일이
 * 있는 폴더를 먼저 뒤지는데, 관리자 권한으로 도는 프로그램이 그 폴더에 놓인 가짜
 * wscapi.dll 을 올리게 된다 (DLL 심기). */
typedef HRESULT (WINAPI *wsc_get_health_fn)(DWORD providers, PWSC_SECURITY_PROVIDER_HEALTH health);

static uint8_t collect_antivirus(void)
{
	WSC_SECURITY_PROVIDER_HEALTH health;
	wsc_get_health_fn get_health;
	HMODULE wsc;
	HRESULT hr;

	wsc = LoadLibraryExW(L"wscapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (wsc == NULL) {
		return POSTURE_UNKNOWN;
	}

	get_health = (wsc_get_health_fn)GetProcAddress(wsc, "WscGetSecurityProviderHealth");
	if (get_health == NULL) {
		FreeLibrary(wsc);
		return POSTURE_UNKNOWN;
	}

	hr = get_health(WSC_SECURITY_PROVIDER_ANTIVIRUS, &health);
	FreeLibrary(wsc);
	if (hr != S_OK) {
		return POSTURE_UNKNOWN;
	}

	/* GOOD 이 아닌 값은 POOR(꺼짐 / 정의 파일 만료), NOTMONITORED(등록된 제품 없음),
	 * SNOOZE(일시 중지) 다. 이유는 달라도 지금 보호받지 못한다는 점은 같다. */
	return health == WSC_SECURITY_PROVIDER_HEALTH_GOOD ? POSTURE_ON : POSTURE_OFF;
}

/* ---- disk encryption ----------------------------------------------------- */
/* BitLocker 의 상태는 WMI 의 Win32_EncryptableVolume 이 가장 정확하다 — ProtectionStatus 가
 * 0(보호 꺼짐) / 1(켜짐) / 2(모름)이다. 암호화는 됐어도 보호가 일시 중지되면 0 이라, 키가 디스크에
 * 그대로 놓인 상태를 켜짐으로 읽지 않는다. 다만 이 클래스는 관리자만 읽을 수 있다. 서비스(SYSTEM)는
 * 읽고, 사용자 권한으로 도는 GUI 와 콘솔은 탐색기가 보여 주는 셸 속성
 * System.Volume.BitLockerProtection 으로 읽는다: 1 은 켜짐, 2 는 꺼짐이고 나머지(암호화 중, 일시
 * 중지, 쓸 수 없음 ...)는 모름으로 둔다.
 *
 * 디스크 암호화는 자주 바뀌지 않는데 WMI 는 한 번에 수십 ms 가 든다. 2초마다 부르는 keepalive 에
 * 그대로 얹지 않고 1분 동안 같은 답을 쓴다. */
#define DISK_CACHE_MS	60000

/* 관리자 권한(또는 SYSTEM)으로 도는가. */
static int process_elevated(void)
{
	TOKEN_ELEVATION e;
	HANDLE tok;
	DWORD len = 0;
	int up = 0;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
		if (GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &len)) {
			up = e.TokenIsElevated != 0;
		}
		CloseHandle(tok);
	}
	return up;
}

static uint8_t disk_from_wmi(const wchar_t *drive)
{
	IWbemLocator *loc = NULL;
	IWbemServices *svc = NULL;
	IEnumWbemClassObject *en = NULL;
	IWbemClassObject *obj = NULL;
	BSTR ns = NULL, lang = NULL, query = NULL;
	wchar_t q[128];
	uint8_t state = POSTURE_UNKNOWN;
	ULONG got = 0;
	VARIANT v;

	VariantInit(&v);
	swprintf(q, sizeof(q) / sizeof(q[0]),
			L"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '%ls'", drive);
	ns = SysAllocString(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
	lang = SysAllocString(L"WQL");
	query = SysAllocString(q);
	if (!ns || !lang || !query) {
		goto out;
	}

	if (FAILED(CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
				&IID_IWbemLocator, (void **)&loc)) ||
			FAILED(loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL, &svc))) {
		goto out;
	}
	/* 이 프로세스의 COM 보안을 바꾸지 않고(CoInitializeSecurity 는 프로세스에 한 번뿐이다) 이 프록시만
	 * 호출자 신원으로 부르게 한다. */
	if (FAILED(CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
				RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
		goto out;
	}
	if (FAILED(svc->lpVtbl->ExecQuery(svc, lang, query,
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en)) ||
			en->lpVtbl->Next(en, 5000, 1, &obj, &got) != WBEM_S_NO_ERROR || got != 1) {
		goto out;
	}
	if (SUCCEEDED(obj->lpVtbl->Get(obj, L"ProtectionStatus", 0, &v, NULL, NULL)) &&
			(v.vt == VT_I4 || v.vt == VT_UI4)) {
		state = v.lVal == 1 ? POSTURE_ON : v.lVal == 0 ? POSTURE_OFF : POSTURE_UNKNOWN;
	}

out:
	VariantClear(&v);
	if (obj) obj->lpVtbl->Release(obj);
	if (en) en->lpVtbl->Release(en);
	if (svc) svc->lpVtbl->Release(svc);
	if (loc) loc->lpVtbl->Release(loc);
	SysFreeString(ns);
	SysFreeString(lang);
	SysFreeString(query);
	return state;
}

static uint8_t disk_from_shell(const wchar_t *drive)
{
	IShellItem2 *item = NULL;
	PROPERTYKEY key;
	PROPVARIANT pv;
	wchar_t root[8];
	uint8_t state = POSTURE_UNKNOWN;
	ULONG val;

	PropVariantInit(&pv);
	swprintf(root, sizeof(root) / sizeof(root[0]), L"%ls\\", drive);
	if (FAILED(PSGetPropertyKeyFromName(L"System.Volume.BitLockerProtection", &key)) ||
			FAILED(SHCreateItemFromParsingName(root, NULL, &IID_IShellItem2, (void **)&item)) ||
			FAILED(item->lpVtbl->GetProperty(item, &key, &pv)) ||
			FAILED(PropVariantToUInt32(&pv, &val))) {
		goto out;
	}
	state = val == 1 ? POSTURE_ON : val == 2 ? POSTURE_OFF : POSTURE_UNKNOWN;

out:
	PropVariantClear(&pv);
	if (item) item->lpVtbl->Release(item);
	return state;
}

static uint8_t collect_disk(void)
{
	static uint8_t cached = POSTURE_UNKNOWN;
	static ULONGLONG cached_at;
	static int have;
	ULONGLONG now = GetTickCount64();
	wchar_t drive[8];
	uint8_t state;
	HRESULT init;
	DWORD n;

	if (have && now - cached_at < DISK_CACHE_MS) {
		return cached;
	}

	/* 시스템 드라이브("C:"). 못 읽으면 모름. */
	n = GetEnvironmentVariableW(L"SystemDrive", drive, sizeof(drive) / sizeof(drive[0]));
	if (n != 2 || drive[1] != L':') {
		return POSTURE_UNKNOWN;
	}

	/* collect_firewall 과 같은 규칙으로 COM 을 연다. */
	init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(init) && init != RPC_E_CHANGED_MODE) {
		return POSTURE_UNKNOWN;
	}
	/* 관리자가 아니면 WMI 는 거부를 바로 알려 주지 않고 시간 제한(5초)까지 기다린다. 핸드셰이크의
	 * AUTH 를 만드는 중에 그만큼 멈추면 서버가 준 nonce 의 수명이 지나 버린다. 권한이 없으면 묻지 않는다. */
	state = process_elevated() ? disk_from_wmi(drive) : POSTURE_UNKNOWN;
	if (state == POSTURE_UNKNOWN) {
		state = disk_from_shell(drive);
	}
	if (SUCCEEDED(init)) {
		CoUninitialize();
	}

	cached = state;
	cached_at = now;
	have = 1;
	return state;
}

void posture_collect(posture_t *out)
{
	memset(out, 0, sizeof(*out));

	collect_os(out);
	out->firewall = collect_firewall();
	out->antivirus = collect_antivirus();
	out->disk = collect_disk();
}
