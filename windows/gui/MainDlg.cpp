#include "framework.h"
#include <uxtheme.h>
#include <windowsx.h>
#include <time.h>
#include "resource.h"
#include "MainDlg.h"
#include "EnrollDlg.h"
#include "PacketText.h"
#include "DiagDlg.h"
#include "SettingsDlg.h"
#include "Portal.h"

#include <wtsapi32.h>

#ifdef _MSC_VER
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "wtsapi32.lib")
#endif

/* 탐색기가 다시 뜨면 알림 영역의 아이콘이 모두 사라진다. 새 작업 표시줄이 만들어질 때
 * 모든 최상위 창에 이 메시지가 오므로, 받으면 아이콘을 다시 단다. */
static const UINT WM_TASKBAR_CREATED = RegisterWindowMessageW(L"TaskbarCreated");


CMainDlg::CMainDlg(CWnd *parent)
	: CDialogEx(IDD_MAIN, parent)
	, m_session(nullptr)
	, m_state(TUNNEL_STATE_STOPPED)
	, m_connected_at(0)
	, m_deny_reason(0)
	, m_posture_ticks(0)
	, m_session_idx(0)
	, m_link(VPN_REMOTE_DOWN)
	, m_stopping(false)
	, m_diag(m_store, m_logLines)
	, m_login_thread(nullptr)
	, m_login_cancel(nullptr)
	, m_login_interactive(false)
	, m_login_gen(0)
	, m_refresh_at(0)
	, m_expired_retry(false)
	, m_expiry_stage(0)
	, m_notified_login(0)
	, m_suspended(false)
	, m_tray_added(false)
	, m_told_tray(false)
	, m_exiting(false)
	, m_notified_deny(0)
	, m_status_icon(ICON_POWER)
	, m_status_color(0)
	, m_status_hint_color(0)
{
	ZeroMemory(&m_fonts, sizeof(m_fonts));
	ZeroMemory(&m_local, sizeof(m_local));
	ZeroMemory(&m_login, sizeof(m_login));
	m_tokens.expires_at = 0;

	static const LPCTSTR checks[CHECK_COUNT] = {
		_T("방화벽"), _T("백신"), _T("디스크 암호화"), _T("OS 빌드"), _T("서버 판정"),
	};
	static const LPCTSTR info[INFO_COUNT] = {
		_T("사용자"), _T("서버"), _T("터널 주소"), _T("주고받은 데이터"), _T("기기 ID"),
	};

	for (int i = 0; i < CHECK_COUNT; i++) {
		m_checks[i].name = checks[i];
		m_checks[i].level = LEVEL_NONE;
	}
	for (int i = 0; i < INFO_COUNT; i++) {
		m_info[i].name = info[i];
		m_info[i].level = LEVEL_NONE;
	}
}

BEGIN_MESSAGE_MAP(CMainDlg, CDialogEx)
	ON_BN_CLICKED(IDC_CONNECT, &CMainDlg::OnConnect)
	ON_BN_CLICKED(IDC_ENROLL, &CMainDlg::OnEnroll)
	ON_BN_CLICKED(IDC_DIAG, &CMainDlg::OnDiag)
	ON_BN_CLICKED(IDC_SETTINGS, &CMainDlg::OnSettings)
	ON_BN_CLICKED(IDC_LOGIN, &CMainDlg::OnLogin)
	ON_WM_DESTROY()
	ON_WM_SIZE()
	ON_WM_TIMER()
	ON_WM_CTLCOLOR()
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_DRAWITEM()
	ON_WM_SYSCOLORCHANGE()
	ON_MESSAGE(WM_PRINTCLIENT, &CMainDlg::OnPrintClient)
	ON_MESSAGE(WM_VPN_LOG, &CMainDlg::OnVpnLog)
	ON_MESSAGE(WM_VPN_STATE, &CMainDlg::OnVpnState)
	ON_MESSAGE(WM_VPN_DONE, &CMainDlg::OnVpnDone)
	ON_MESSAGE(WM_VPN_PACKETS, &CMainDlg::OnVpnPackets)
	ON_MESSAGE(WM_VPN_SERVICE, &CMainDlg::OnVpnService)
	ON_MESSAGE(WM_VPN_DEVICE, &CMainDlg::OnVpnDevice)
	ON_MESSAGE(WM_VPN_ERROR, &CMainDlg::OnVpnError)
	ON_MESSAGE(WM_VPN_LOGIN, &CMainDlg::OnVpnLogin)
	ON_MESSAGE(WM_LOGIN_DONE, &CMainDlg::OnLoginDone)
	ON_MESSAGE(WM_PORTAL_DONE, &CMainDlg::OnPortalDone)
	ON_MESSAGE(WM_INVITE, &CMainDlg::OnInvite)
	ON_WM_COPYDATA()
	ON_WM_LBUTTONUP()
	ON_WM_SETCURSOR()
	ON_MESSAGE(WM_WTSSESSION_CHANGE, &CMainDlg::OnSessionChange)
	ON_MESSAGE(WM_TRAYICON, &CMainDlg::OnTrayIcon)
	ON_REGISTERED_MESSAGE(WM_TASKBAR_CREATED, &CMainDlg::OnTaskbarCreated)
END_MESSAGE_MAP()

BOOL CMainDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	/* 큰 아이콘(Alt+Tab)과 작은 아이콘(제목 표시줄)을 각자의 크기로 읽는다. LoadIcon 은
	 * 32픽셀 하나만 주므로 작은 쪽은 줄여 그려져 뭉개진다. */
	SetIcon(AfxGetApp()->LoadIcon(IDI_APP), TRUE);
	SetIcon(static_cast<HICON>(LoadImageW(AfxGetInstanceHandle(), MAKEINTRESOURCEW(IDI_APP),
			IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
			LR_SHARED)), FALSE);
	ui::MatchTitleBar(GetSafeHwnd());

	/* 글꼴은 다이얼로그 글꼴에서 파생한다. 그 글꼴은 이미 시스템 DPI 에 맞춰져 있다. */
	ui::CreateFonts(reinterpret_cast<HFONT>(SendMessage(WM_GETFONT)), &m_fonts);
	m_card_brush.CreateSolidBrush(ui::Colors().card);

	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_CONNECT), ui::BUTTON_PRIMARY);
	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_SETTINGS), ui::BUTTON_LINK);
	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_ENROLL), ui::BUTTON_LINK);
	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_DIAG), ui::BUTTON_LINK);
	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_LOGIN), ui::BUTTON_CARD_LINK);

	/* 연결 버튼은 이 창에서 가장 중요한 버튼이다. 글자도 한 단계 키운다. */
	GetDlgItem(IDC_CONNECT)->SetFont(CFont::FromHandle(m_fonts.strong));

	LoadSettings();

	/* 창이 만들어진 뒤여야 PostMessage 대상 HWND 를 넘길 수 있다. */
	m_session = vpn_session_create(GetSafeHwnd());
	if (!m_session) {
		AfxMessageBox(_T("세션을 만들 수 없습니다."), MB_ICONERROR);
		EndDialog(IDCANCEL);
		return TRUE;
	}

	LoadDeviceId();
	RefreshPosture(true);

	/* 지난번에 로그인해 둔 채였으면 브라우저 없이 이어서 로그인한다. */
	m_login_cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!m_issuer.IsEmpty() && oidc::LoadRefresh(LoginConfig(), &m_tokens.refresh)) {
		StartLogin(false);
	}
	UpdateLoginButton();

	/* 사용자 전환이나 원격 세션이 끊기는 것을 알아야 한다 (OnSessionChange). */
	WTSRegisterSessionNotification(GetSafeHwnd(), NOTIFY_FOR_THIS_SESSION);

	UpdateInfo();
	SetUiState(TUNNEL_STATE_STOPPED);
	SetTimer(TIMER_TICK_ID, TIMER_TICK_MS, nullptr);

	m_tray_tip = _T("ztgate \x2014 ") + m_status_title;
	TrayAdd();

	/* 창 크기는 내용에 맞춘 고정 크기다. 늘려도 보여 줄 것이 더 없다. */
	FitWindow();

	SetPropW(GetSafeHwnd(), kWindowProp, reinterpret_cast<HANDLE>(1));
	/* 링크를 눌러 뜬 둘째 GUI 는 무결성 수준이 이 창보다 낮을 수 있다 (브라우저가 띄운다). 그러면
	 * UIPI 가 WM_COPYDATA 를 버린다. */
	ChangeWindowMessageFilterEx(GetSafeHwnd(), WM_COPYDATA, MSGFLT_ALLOW, nullptr);
	if (!m_invite.IsEmpty()) {
		PostMessage(WM_INVITE);
	}

	return TRUE;
}

/* 두 번째로 뜬 GUI 가 보낸 것 (VpnGuiApp.cpp). 링크가 없으면 앞으로 나오기만 한다. */
BOOL CMainDlg::OnCopyData(CWnd *, COPYDATASTRUCT *cd)
{
	if (cd->dwData != kCopyInvite || cd->cbData < sizeof(wchar_t) || cd->cbData > 4096 ||
			cd->cbData % sizeof(wchar_t) != 0) {
		return FALSE;
	}

	const CString link(static_cast<LPCWSTR>(cd->lpData), static_cast<int>(cd->cbData / sizeof(wchar_t)) - 1);

	ShowFromTray();
	if (invite_like(link)) {
		m_invite = link;
		PostMessage(WM_INVITE);
	}
	return TRUE;
}

LRESULT CMainDlg::OnInvite(WPARAM, LPARAM)
{
	ShowFromTray();
	if (m_invite.IsEmpty()) {
		return 0;
	}

	/* 링크로 막 뜬 참이면 아직 서비스에 붙지 않았고, 이 PC 가 등록됐는지도 모른다. 알게 되면
	 * OnVpnDevice 가 다시 부른다. 붙지 못한 채 오래 걸리면 OnTimer 가 까닭을 알린다. */
	if (m_link != VPN_REMOTE_UP || !m_device_known) {
		if (m_invite_at == 0) {
			m_invite_at = GetTickCount64();
		}
		return 0;
	}

	const CString link = m_invite;

	m_invite.Empty();
	m_invite_at = 0;

	/* 같은 링크를 또 눌렀다. 등록 창은 하나만 둔다. */
	if (m_enrolling) {
		return 0;
	}
	Enroll(link);
	return 0;
}

/* ---- 설정 저장 / 복원 --------------------------------------------------- */
void CMainDlg::LoadSettings()
{
	CWinApp *app = AfxGetApp();

	m_adapter = app->GetProfileString(_T("conn"), _T("adapter"), _T("ztgate"));
	m_server = app->GetProfileString(_T("conn"), _T("server"), _T(""));
	m_port = app->GetProfileString(_T("conn"), _T("port"), _T("9000"));
	m_issuer = app->GetProfileString(_T("login"), _T("issuer"), _T(""));
	m_client_id = app->GetProfileString(_T("login"), _T("client_id"), _T("ztgate"));
	m_scope = app->GetProfileString(_T("login"), _T("scope"), _T("openid"));

	/* 정책이 정한 것은 그대로 쓴다. 사용자 설정에는 덮어쓰지 않는다 — 정책이 빠지면 원래대로. */
	policy_load(&m_policy);
	if (m_policy.has_servers) {
		m_server = m_policy.servers_text;
		m_port.Format(_T("%u"), (unsigned)m_policy.port);
	}
	if (m_policy.issuer[0] != L'\0') {
		m_issuer = m_policy.issuer;
		if (m_policy.client_id[0] != L'\0') {
			m_client_id = m_policy.client_id;
		}
	}
}

void CMainDlg::SaveSettings()
{
	CWinApp *app = AfxGetApp();

	/* 정책이 정한 값은 사용자 설정으로 남기지 않는다. 정한 것만 건너뛴다 — 나머지는 사용자 것이다. */
	app->WriteProfileString(_T("conn"), _T("adapter"), m_adapter);
	if (!m_policy.has_servers) {
		app->WriteProfileString(_T("conn"), _T("server"), m_server);
		app->WriteProfileString(_T("conn"), _T("port"), m_port);
	}
	if (m_policy.issuer[0] == L'\0') {
		app->WriteProfileString(_T("login"), _T("issuer"), m_issuer);
	}
	if (m_policy.issuer[0] == L'\0' || m_policy.client_id[0] == L'\0') {
		app->WriteProfileString(_T("login"), _T("client_id"), m_client_id);
	}
	app->WriteProfileString(_T("login"), _T("scope"), m_scope);
}

/* 토큰은 그것을 준 IdP 와 클라이언트의 것이다. 바뀌었으면 들고 있던 로그인을 버린다. */
void CMainDlg::ChangeLogin(const CString &issuer, const CString &client_id, const CString &scope)
{
	if (issuer == m_issuer && client_id == m_client_id && scope == m_scope) {
		return;
	}

	/* 옛 설정으로 로그아웃한다 — refresh token 폐기는 그것을 준 IdP 에 해야 한다. */
	Logout(_T("로그인 설정이 바뀌어 로그아웃했습니다"));
	m_issuer = issuer;
	m_client_id = client_id;
	m_scope = scope;
	m_login_error.Empty();

	CRect rc;
	GetClientRect(&rc);
	LayoutChildren(rc.Width(), rc.Height());	/* 로그인 버튼이 생기거나 사라진다 */
}

/* 그룹 정책이 새로 내려오면(gpupdate) 껐다 켜지 않아도 따른다. */
void CMainDlg::ReloadPolicy()
{
	ztgate_policy_t now;

	policy_load(&now);
	if (memcmp(&now, &m_policy, sizeof(now)) == 0) {
		return;
	}

	const CString issuer = m_issuer, client_id = m_client_id, scope = m_scope;

	AppendLog(_T("[gui] 관리 정책이 바뀌어 다시 읽었습니다"));
	LoadSettings();

	const CString new_issuer = m_issuer, new_client_id = m_client_id, new_scope = m_scope;

	m_issuer = issuer;
	m_client_id = client_id;
	m_scope = scope;
	ChangeLogin(new_issuer, new_client_id, new_scope);

	UpdateInfo();
	UpdateLoginButton();
	SetUiState(m_state);
}

/* 설정 창을 연다. bad_id 가 있으면 그 칸을 가리키며 연다. 저장했으면 true. */
bool CMainDlg::EditSettings(int bad_id, const CString &why)
{
	CSettingsDlg dlg(this);

	dlg.m_server = m_server;
	dlg.m_port = m_port;
	dlg.m_adapter = m_adapter;
	dlg.m_issuer = m_issuer;
	dlg.m_client_id = m_client_id;
	dlg.m_scope = m_scope;
	dlg.m_lock_servers = m_policy.has_servers != 0;
	dlg.m_lock_issuer = m_policy.issuer[0] != L'\0';
	dlg.m_lock_client_id = dlg.m_lock_issuer && m_policy.client_id[0] != L'\0';
	if (bad_id != 0) {
		dlg.PointAt(bad_id, why);
	}
	if (dlg.DoModal() != IDOK) {
		return false;
	}

	m_server = dlg.m_server;
	m_port = dlg.m_port;
	m_adapter = dlg.m_adapter;
	ChangeLogin(dlg.m_issuer, dlg.m_client_id, dlg.m_scope);

	SaveSettings();
	UpdateInfo();
	UpdateLoginButton();

	return true;
}

/* 연결 중에는 바꿔도 반영되지 않는다. 링크를 회색으로 죽여 두면 고장처럼 보이므로,
 * 누를 수 있게 두고 왜 안 되는지와 할 일을 알려 준다. */
void CMainDlg::OnSettings()
{
	if (m_state != TUNNEL_STATE_STOPPED) {
		AfxMessageBox(_T("연결 중에는 설정을 바꿀 수 없습니다.\n먼저 [연결 해제] 를 누른 뒤 다시 열어 주세요."),
				MB_ICONINFORMATION);
		return;
	}

	EditSettings(0, CString());
}

/* 저장된 설정이 쓸 수 있는 값인가. 아니면 설정 창을 그 칸에 맞춰 연다 — 레지스트리를
 * 손으로 고쳤거나 예전 버전이 남긴 값일 수 있다. */
bool CMainDlg::SettingsUsable()
{
	CString why;
	int bad = 0;

	if (CSettingsDlg::Check(m_server, m_port, m_adapter, &bad, &why)) {
		return true;
	}

	return EditSettings(bad, why);
}

/* ---- 설정 읽기 ---------------------------------------------------------- */
bool CMainDlg::BuildConfig(tunnel_config_t &cfg)
{
	ZeroMemory(&cfg, sizeof(cfg));
	/* on_packet 을 쓰므로 코어의 패킷 텍스트 로그는 필요 없다. */
	cfg.log_packets = 0;

	if (!SettingsUsable()) {
		return false;
	}

	/* adapter_name 은 wchar_t 배열이고 cfg 는 구조체째로 복사되므로
	 * CString 의 수명에 의존하지 않는다. 값은 SettingsUsable 이 확인했다. */
	wcscpy_s(cfg.adapter_name, TUNNEL_ADAPTER_NAME_LEN, m_adapter);
	wcscpy_s(cfg.servers, TUNNEL_SERVERS_LEN, m_server);
	cfg.server_port = static_cast<uint16_t>(_ttoi(m_port));

	/* 터널은 서비스가 연다. 이 프로그램은 어디로 붙을지만 알려 준다 — 기기의 키는
	 * 서비스만 읽을 수 있는 곳에 있고 여기로는 오지 않는다. */
	if (!ServiceReady()) {
		return false;
	}

	if (m_device_id.IsEmpty()) {
		AfxMessageBox(_T("등록되지 않은 기기입니다.\n\n")
				_T("[기기 등록...] 에 관리자에게 받은 등록 코드를 적어 주세요."), MB_ICONWARNING);
		/* 어디로 가야 하는지 말로만 하지 않고 그 버튼으로 데려다 준다. */
		GotoDlgCtrl(GetDlgItem(IDC_ENROLL));
		return false;
	}

	return true;
}

/* ---- 버튼 -------------------------------------------------------------- */
/* 버튼은 하나다. 터널이 닫혀 있으면 "연결", 열려 있으면 "연결 해제"다. 두 버튼을
 * 나란히 두면 늘 한쪽은 눌리지 않는 채로 자리만 차지한다. */
void CMainDlg::OnConnect()
{
	tunnel_config_t cfg;

	if (vpn_session_active(m_session)) {
		/* AlwaysOn 이면 버튼과 메뉴가 이미 막혀 있다 (SetUiState, TrayMenu). 서비스도 받지 않는다. */
		if (!m_policy.always_on) {
			RequestDisconnect();
		}
		return;
	}

	if (m_server.IsEmpty()) {
		AfxMessageBox(_T("연결할 서버가 아직 정해지지 않았습니다.\n\n")
				_T("관리자에게 받은 초대 링크가 있으면 [기기 등록] 에 붙여 넣으세요. 서버와 포트도 함께 정해집니다.\n")
				_T("서버 주소를 알고 있으면 [설정] 에 적어 주세요."), MB_ICONINFORMATION);
		GotoDlgCtrl(GetDlgItem(m_device_id.IsEmpty() ? IDC_ENROLL : IDC_SETTINGS));
		return;
	}

	if (!BuildConfig(cfg)) {
		return;
	}

	SaveSettings();

	/* 지난 연결의 판정과 보고 값은 새 연결과 무관하다. */
	m_deny_reason = 0;
	m_session_idx = 0;

	if (vpn_session_start(m_session, &cfg) < 0) {
		AppendLog(_T("[gui] 워커 스레드를 만들 수 없습니다"));
		return;
	}

	/* tunnel_run 도 곧 CONNECTING 을 보내지만, 버튼을 누른 즉시 반응을 보이도록
	 * 여기서 한 번 더 바꿔 준다. */
	SetUiState(TUNNEL_STATE_CONNECTING);
}

void CMainDlg::RequestDisconnect()
{
	if (m_stopping) {
		return;
	}

	AppendLog(_T("[gui] 해제 요청"));
	vpn_session_stop(m_session);

	/* 여기서 워커를 기다리지 않는다. 기다리면 UI 가 멈추고, 그 사이 워커가 보낸
	 * PostMessage 도 처리되지 않는다. 워커가 끝나면 WM_VPN_DONE 이 오고 거기서 join 한다.
	 * 그동안 버튼은 잠그고 무슨 일이 진행 중인지 적어 둔다. */
	m_stopping = true;
	SetUiState(m_state);
}

/* 이 기기의 ID 와 키를 새로 만든다. */
void CMainDlg::OnEnroll()
{
	Enroll(CString());
}

/* prefill 은 등록 창의 칸에 미리 넣을 것 (초대 링크). 칸에는 코드나 링크를 적는다. */
void CMainDlg::Enroll(const CString &prefill)
{
	/* 등록 창과 메시지 상자는 메시지를 돌리므로 그사이에 또 온 링크가 창을 하나 더 열 수 있다 (OnInvite). */
	struct Busy {
		bool *flag;
		explicit Busy(bool *f) : flag(f) { *flag = true; }
		~Busy() { *flag = false; }
	} busy(&m_enrolling);
	device_t dev;
	invite_t inv;
	const bool invited = invite_parse(prefill, &inv) == 0;

	if (!ServiceReady()) {
		return;
	}

	/* 돌고 있는 터널은 예전 키로 인증한 세션이다. 지금 키를 바꾸면 화면의 기기 ID 와
	 * 실제로 쓰이는 키가 어긋난다. 서비스도 터널이 돌고 있는 동안에는 받지 않는다. 연결을
	 * 원하기만 하는 중(AlwaysOn 인데 아직 등록되지 않았다)이면 받는다. */
	if (vpn_remote_running(m_session)) {
		AfxMessageBox(m_policy.always_on ?
				_T("회사 정책으로 늘 연결되는 PC 라 터널이 열려 있는 동안에는 다시 등록할 수 없습니다.\n\n관리자에게 문의하세요.") :
				_T("연결을 해제한 뒤에 등록하세요."), MB_ICONINFORMATION);
		return;
	}

	if (!m_device_id.IsEmpty()) {
		if (AfxMessageBox(_T("이미 등록된 기기입니다.\n\n")
				_T("새 키를 만들면 서버에 등록해 둔 지금의 키로는 접속할 수 없게 됩니다.\n")
				_T("새로 만들까요?"), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
			return;
		}
	}

	if (!prefill.IsEmpty() && !invited) {
		AfxMessageBox(_T("초대 링크가 아닙니다. 관리자에게 링크를 다시 받아 주세요."), MB_ICONWARNING);
		return;
	}

	/* 보통은 관리자가 준 초대 링크나 등록 코드로 올린다. 코드만 적으면 연결 설정의 서버에 올린다 —
	 * 등록한 서버와 연결할 서버가 다를 이유가 없다. 초대 링크로 왔으면 링크의 서버를 보여 준다
	 * (정책이 서버를 정했으면 정책의 것). 서버가 아직 없으면 링크를 붙여 넣으라고 한다. */
	if (!invited && !m_server.IsEmpty() && !SettingsUsable()) {
		return;
	}

	CString where = _T("올릴 서버  ") + m_server + _T(" : ") + m_port;

	if (invited && !m_policy.has_servers) {
		where.Format(_T("올릴 서버  %s : %u"), inv.servers, (unsigned)inv.port);
	}
	else if (m_server.IsEmpty()) {
		where = _T("서버가 아직 정해지지 않았습니다. 초대 링크를 붙여 넣어 주세요.");
	}
	SecureZeroMemory(&inv, sizeof(inv));

	CEnrollCodeDlg ask(where, this);
	ask.m_code = prefill;
	INT_PTR choice = ask.DoModal();

	if (choice == CEnrollCodeDlg::RESULT_MANUAL) {
		/* 코드 없이: 서비스가 ID 와 키를 만들어 저장하고 한 번 돌려준다. 그것을 보여
		 * 주고, 관리자가 손으로 서버에 옮겨 적는다. */
		{
			CWaitCursor wait;

			if (vpn_remote_enroll_manual(m_session, &dev) != DEVICE_OK) {
				ShowEnrollError();
				return;
			}
		}

		{
			CEnrollDlg dlg(dev, this);

			SecureZeroMemory(&dev, sizeof(dev));
			dlg.DoModal();
		}

		LoadDeviceId();
		RefreshPosture(false);
		AppendLog(_T("[gui] 기기 등록 (수동): ") + m_device_id);
		return;
	}
	if (choice != IDOK) {
		return;
	}

	/* 칸에 링크를 붙여 넣었으면 링크의 서버와 포트로 올린다. 연결 설정으로 삼는 것은 서버가
	 * 받아 준 뒤다 — 틀린 링크 하나로 쓰던 설정을 잃지 않게. 정책이 서버를 정했으면 그대로 두고
	 * 코드만 쓴다 — 링크가 관리자의 정책을 넘어서면 안 된다. */
	CStringA code(ask.m_code);
	CString servers = m_server;
	CString port_text = m_port;

	if (invite_like(ask.m_code)) {
		if (invite_parse(ask.m_code, &inv) < 0) {
			AfxMessageBox(_T("초대 링크를 읽을 수 없습니다. 관리자에게 링크를 다시 받아 주세요."), MB_ICONWARNING);
			return;
		}
		if (!m_policy.has_servers) {
			servers = inv.servers;
			port_text.Format(_T("%u"), (unsigned)inv.port);
		}
		code = inv.code;
		SecureZeroMemory(&inv, sizeof(inv));
	}
	else if (servers.IsEmpty()) {
		AfxMessageBox(_T("어느 서버에 올릴지 아직 정해지지 않았습니다.\n\n")
				_T("관리자에게 받은 초대 링크를 붙여 넣거나, [설정] 에서 서버를 먼저 적어 주세요."), MB_ICONINFORMATION);
		return;
	}

	const uint16_t port = static_cast<uint16_t>(_ttoi(port_text));

	int result;

	{
		/* 서비스가 서버와 주고받는 동안 창이 멈춘다. 길어야 수십 초이고, 그동안 할 수
		 * 있는 일도 없다. 신원을 만들고 저장하는 것은 서비스다 — 키는 이 프로그램을
		 * 지나가지 않는다. */
		CWaitCursor wait;

		result = vpn_remote_enroll(m_session, servers, port, code);
	}

	const bool saved = true;	/* 저장은 서비스가 했다. 못 했으면 result 가 OK 가 아니다 */

	switch (result) {
	case TUNNEL_ENROLL_OK:
		if (!saved) {
			AfxMessageBox(_T("서버에는 등록됐지만 이 PC 에 신원을 저장하지 못했습니다.\n\n")
					_T("관리자에게 그 기기를 지우고 새 코드를 달라고 하세요."), MB_ICONERROR);
			return;
		}
		break;
	case TUNNEL_ENROLL_BAD_CODE:
		AfxMessageBox(_T("등록 코드가 아닙니다. 글자와 숫자 25자입니다."), MB_ICONWARNING);
		return;
	case TUNNEL_ENROLL_NO_RESPONSE:
		AfxMessageBox(_T("서버가 답하지 않습니다. 서버 주소와 포트를 확인하세요."), MB_ICONWARNING);
		return;
	case TUNNEL_ENROLL_REJECTED:
		AfxMessageBox(_T("서버가 이 코드를 받지 않습니다.\n\n")
				_T("잘못 적었거나, 만료됐거나, 이미 쓰인 코드입니다."), MB_ICONWARNING);
		return;
	case TUNNEL_ENROLL_CONFLICT:
		AfxMessageBox(_T("이 기기나 이 코드에 묶인 터널 주소가 이미 서버에 있습니다.\n\n")
				_T("관리자에게 새 코드를 달라고 하세요."), MB_ICONWARNING);
		return;
	case TUNNEL_ENROLL_SERVER_FAILED:
		AfxMessageBox(_T("서버가 기기를 저장하지 못했습니다. 관리자에게 알려 주세요."), MB_ICONERROR);
		return;
	default:
		ShowEnrollError();
		return;
	}

	if (servers != m_server || port_text != m_port) {
		m_server = servers;
		m_port = port_text;
		SaveSettings();
		UpdateInfo();
		AppendLog(_T("[gui] 초대 링크의 서버로 설정: ") + m_server + _T(" : ") + m_port);
	}

	LoadDeviceId();
	RefreshPosture(false);
	AppendLog(_T("[gui] 기기 등록: ") + m_device_id);
	AfxMessageBox(_T("등록됐습니다 (") + servers + _T(").\n\n") + (vpn_remote_wanted(m_session) ?
			CString(_T("곧 자동으로 연결됩니다.")) : CString(_T("이제 [연결]을 누르면 됩니다."))), MB_ICONINFORMATION);
}

/* 서비스가 등록을 끝내지 못했다 (TUNNEL_ENROLL_ERROR, DEVICE_ERROR). 무엇을 하면 되는지 말한다. */
void CMainDlg::ShowEnrollError()
{
	LPCTSTR text;

	switch (vpn_remote_enroll_error(m_session)) {
	case IPC_ERR_BUSY:
		text = _T("터널이 열려 있는 동안에는 등록할 수 없습니다.\n\n")
			_T("[연결 해제] 를 누른 뒤 다시 해 주세요. 회사 정책으로 늘 연결되는 PC 면 관리자에게 문의하세요.");
		break;
	case IPC_ERR_BAD_REQUEST:
		text = _T("서비스가 등록 요청을 받지 않았습니다. 서버 주소나 등록 코드의 모양이 맞지 않습니다.\n\n")
			_T("관리자에게 초대 링크를 다시 받거나 [설정] 의 서버 주소를 확인하세요.");
		break;
	case IPC_ERR_NOT_ENROLLED:
		text = _T("이 PC 는 아직 등록되지 않았습니다.\n\n")
			_T("관리자에게 받은 초대 링크나 등록 코드로 다시 해 주세요.");
		break;
	default:
		/* 등록하는 동안에는 메시지를 돌리지 않아 m_link 가 늦다. 지금 것을 묻는다. */
		text = vpn_remote_link(m_session) != VPN_REMOTE_UP ?
			_T("등록하는 동안 ztgate 서비스와의 연결이 끊겼습니다.\n\n")
			_T("잠시 뒤 다시 해 주세요. 계속되면 IT 담당자에게 알려 주세요.") :
			_T("기기 등록에 실패했습니다.\n\n")
			_T("[진단] 의 로그를 확인하고, 계속되면 IT 담당자에게 알려 주세요.");
		break;
	}
	AfxMessageBox(text, MB_ICONWARNING);
}

/* ---- 워커 -> UI -------------------------------------------------------- */
LRESULT CMainDlg::OnVpnLog(WPARAM, LPARAM lParam)
{
	char *line = reinterpret_cast<char *>(lParam);

	if (line) {
		/* 워커가 넘긴 소유권이 여기서 끝난다. */
		AppendLog(CString(line));
		vpn_session_free_log(line);
	}

	return 0;
}

/* 서버에 닿지 못한 채 8초가 지나면 묻기 시작하고, 그 뒤로는 30초마다. 연결되면 잊는다. */
void CMainDlg::CheckPortal()
{
	const bool trouble = m_state == TUNNEL_STATE_CONNECTING || m_state == TUNNEL_STATE_RECONNECTING;
	const ULONGLONG now = GetTickCount64();

	if (!trouble) {
		m_trouble_since = 0;
		m_portal_told = false;
		if (m_portal != portal::UNKNOWN) {
			m_portal = portal::UNKNOWN;
			UpdateStatus();
		}
		return;
	}
	if (m_trouble_since == 0) {
		m_trouble_since = now;
	}
	if (m_portal_thread || now - m_trouble_since < 8000 || (m_portal_at != 0 && now - m_portal_at < 30000)) {
		return;
	}
	m_portal_at = now;
	m_portal_thread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
		::PostMessage(static_cast<HWND>(p), WM_PORTAL_DONE, portal::Probe(), 0);
		return 0;
	}, GetSafeHwnd(), 0, nullptr);
}

LRESULT CMainDlg::OnPortalDone(WPARAM wParam, LPARAM)
{
	if (m_portal_thread) {
		WaitForSingleObject(m_portal_thread, INFINITE);
		CloseHandle(m_portal_thread);
		m_portal_thread = nullptr;
	}
	if (m_state != TUNNEL_STATE_CONNECTING && m_state != TUNNEL_STATE_RECONNECTING) {
		return 0;
	}
	m_portal = static_cast<int>(wParam);
	if (m_portal == portal::CAPTIVE && !m_portal_told) {
		m_portal_told = true;
		AppendLog(_T("[gui] 이 네트워크는 로그인 페이지(캡티브 포털)가 가로채고 있습니다"));
		TrayNotify(_T("로그인이 필요한 네트워크"),
				_T("이 와이파이는 로그인해야 인터넷을 쓸 수 있습니다. ztgate 창의 안내를 누르면 로그인 페이지가 열립니다."), true);
	}
	UpdateStatus();
	return 0;
}

/* 포털 안내 문구를 누르면 로그인 페이지를 연다. */
void CMainDlg::OnLButtonUp(UINT flags, CPoint pt)
{
	if (m_portal == portal::CAPTIVE && m_rc_hero_text.PtInRect(pt)) {
		ShellExecuteW(GetSafeHwnd(), L"open", portal::kLoginUrl, nullptr, nullptr, SW_SHOWNORMAL);
		return;
	}
	CDialogEx::OnLButtonUp(flags, pt);
}

BOOL CMainDlg::OnSetCursor(CWnd *wnd, UINT hit, UINT msg)
{
	CPoint pt;

	GetCursorPos(&pt);
	ScreenToClient(&pt);
	if (hit == HTCLIENT && m_portal == portal::CAPTIVE && m_rc_hero_text.PtInRect(pt)) {
		::SetCursor(::LoadCursor(nullptr, IDC_HAND));
		return TRUE;
	}
	return CDialogEx::OnSetCursor(wnd, hit, msg);
}

LRESULT CMainDlg::OnVpnState(WPARAM wParam, LPARAM)
{
	tunnel_state_t st = static_cast<tunnel_state_t>(wParam);

	if (st == TUNNEL_STATE_RECONNECTING) {
		m_store.CountRehandshake();
	}
	SetUiState(st);

	return 0;
}

LRESULT CMainDlg::OnVpnDone(WPARAM wParam, LPARAM)
{
	const int ret = static_cast<int>(wParam);

	/* 워커는 이미 반환했으므로 join 은 바로 돌아온다. 핸들을 정리해야 다시 연결할 수 있다. */
	vpn_session_join(m_session, VPN_STOP_TIMEOUT_MS);

	/* 종료 직전에 올라온 패킷이 링에 남아 있을 수 있다. */
	OnVpnPackets(0, 0);

	AppendLog(ret == 0 ? _T("[gui] 정상 종료") : _T("[gui] 오류로 종료"));
	SetUiState(TUNNEL_STATE_STOPPED);

	return 0;
}

LRESULT CMainDlg::OnVpnPackets(WPARAM, LPARAM)
{
	tunnel_packet_t batch[PACKET_DRAIN_BATCH];
	int n;

	/* 0 이 나올 때까지 비운다. 한 번에 전부 가져오지 않고 배치로 끊어
	 * UI 가 한 번에 오래 멈추지 않게 한다. */
	do {
		n = vpn_session_drain_packets(m_session, batch, PACKET_DRAIN_BATCH);
		for (int i = 0; i < n; i++) {
			m_store.Add(batch[i]);
			TrackAuth(batch[i]);
		}
	} while (n == PACKET_DRAIN_BATCH);

	m_store.SetLost(vpn_session_lost_packets(m_session));
	m_diag.PacketsChanged();

	/* 상태 변화(WM_VPN_STATE)와 패킷(WM_VPN_PACKETS)은 따로 오는 메시지라, "거부됨"
	 * 상태가 DENY 패킷보다 먼저 처리될 수 있다. 그때는 SetUiState 가 사유를 아직
	 * 모르므로 사유를 알게 된 여기서도 한 번 더 쓴다. */
	UpdateStatus();
	RefreshPosture(false);

	/* 거부는 사유를 알게 되는 여기서 알린다. 같은 거부를 keepalive 마다 다시 알리지 않는다. */
	if (m_deny_reason != 0 && m_deny_reason != m_notified_deny) {
		m_notified_deny = m_deny_reason;
		TrayNotify(_T("접속 차단됨"), DenyHint(), true);
	}
	else if (m_deny_reason == 0) {
		m_notified_deny = 0;
	}

	return 0;
}

/* 기기 ID 만 보여 준다. device_load 는 키까지 풀어 주므로 쓰지 않을 키는 바로 지운다. */
void CMainDlg::LoadDeviceId()
{
	uint8_t id[DEVICE_ID_LEN];

	m_device_id.Empty();

	/* 신원은 서비스가 갖고 있다. 서비스에 붙기 전에는 등록됐는지조차 알 수 없다. */
	if (vpn_remote_device(m_session, id)) {
		CString t;
		for (int i = 0; i < DEVICE_ID_LEN; i++) {
			t.Format(_T("%02x"), id[i]);
			m_device_id += t;
		}
	}
}

/* 서비스에 붙어 있는가. 아니면 왜 안 되는지와 무엇을 해야 하는지를 알려 준다. */
bool CMainDlg::ServiceReady()
{
	switch (m_link) {
	case VPN_REMOTE_UP:
		return true;
	case VPN_REMOTE_MISMATCH:
		AfxMessageBox(_T("ztgate 서비스와 이 프로그램의 버전이 다릅니다.\n\n")
				_T("업데이트로 서비스만 바뀌었을 수 있습니다. 알림 영역의 ztgate 아이콘을 오른쪽 클릭해 [종료] 를 ")
				_T("누른 뒤 ztgate 를 다시 시작하세요. 그래도 같으면 ztgate 를 다시 설치하고, 계속되면 IT 담당자에게 ")
				_T("알려 주세요."), MB_ICONWARNING);
		return false;
	case VPN_REMOTE_BUSY:
		AfxMessageBox(_T("다른 프로그램이 이미 서비스에 붙어 있습니다.\n\n")
				_T("이 PC 에 로그온한 다른 Windows 사용자의 ztgate 가 서비스를 쓰고 있을 수 있습니다 (사용자 전환, ")
				_T("원격 데스크톱). 그 사용자가 ztgate 를 끝내면 붙습니다. 이 창이 하나 더 떠 있는지도 확인하세요."),
				MB_ICONWARNING);
		return false;
	default:
		AfxMessageBox(_T("터널을 맡는 ztgate 서비스가 돌고 있지 않습니다.\n\n")
				_T("PC 를 다시 시작하거나 ztgate 를 다시 설치해 보세요. ")
				_T("계속되면 IT 담당자에게 알려 주세요."), MB_ICONWARNING);
		return false;
	}
}

/* 서비스와의 연결이 바뀌었다. */
LRESULT CMainDlg::OnVpnService(WPARAM wParam, LPARAM)
{
	m_link = static_cast<int>(wParam);

	switch (m_link) {
	case VPN_REMOTE_UP:
		AppendLog(_T("[gui] 서비스에 붙었습니다"));
		break;
	case VPN_REMOTE_MISMATCH:
		AppendLog(_T("[gui] 서비스가 이 프로그램과 다른 버전입니다"));
		break;
	case VPN_REMOTE_BUSY:
		AppendLog(_T("[gui] 다른 프로그램이 서비스에 붙어 있습니다"));
		break;
	default:
		AppendLog(_T("[gui] 서비스에 닿지 못합니다"));
		break;
	}

	/* 서비스에서 떨어지면 터널이 어떤 상태인지 이 프로그램은 모른다. 열려 있을 수도
	 * 있다. 모르는 것을 "연결됨"으로 보여 주지 않는다. */
	if (m_link != VPN_REMOTE_UP) {
		m_device_known = false;
		m_stopping = false;
		SetUiState(TUNNEL_STATE_STOPPED);
	}

	LoadDeviceId();
	RefreshPosture(false);
	UpdateStatus();

	/* 서비스는 떨어진 GUI 의 토큰을 버린다. 다시 붙었으면 다시 건넨다. */
	if (m_link == VPN_REMOTE_UP) {
		SendToken();
	}

	return 0;
}

LRESULT CMainDlg::OnVpnDevice(WPARAM, LPARAM)
{
	m_device_known = m_link == VPN_REMOTE_UP;
	LoadDeviceId();
	RefreshPosture(false);
	UpdateStatus();

	/* 서비스에 붙기를 기다리던 초대 링크. 이제 이 PC 가 등록됐는지 알고 물을 수 있다. */
	if (m_device_known && !m_invite.IsEmpty()) {
		PostMessage(WM_INVITE);
	}

	return 0;
}

/* 서비스가 명령을 받아 주지 않았다. */
LRESULT CMainDlg::OnVpnError(WPARAM wParam, LPARAM)
{
	switch (wParam) {
	case 1:		/* IPC_ERR_BUSY */
		AppendLog(_T("[gui] 서비스: 터널이 열려 있습니다. 먼저 해제하세요"));
		break;
	case 2:		/* IPC_ERR_NOT_ENROLLED */
		AppendLog(_T("[gui] 서비스: 등록되지 않은 기기입니다"));
		break;
	case 5:		/* IPC_ERR_POLICY */
		AppendLog(_T("[gui] 서비스: 회사 정책(AlwaysOn)으로 연결을 끊을 수 없습니다"));
		m_stopping = false;
		SetUiState(m_state);
		break;
	default:
		AppendLog(_T("[gui] 서비스가 요청을 받지 않았습니다"));
		break;
	}

	/* 연결을 눌러 "연결 중"으로 바꿔 둔 화면을 서비스의 실제 상태로 되돌린다. 열려
	 * 있었다면 곧 STATE 가 다시 온다. */
	if (!vpn_session_active(m_session)) {
		m_stopping = false;
		SetUiState(TUNNEL_STATE_STOPPED);
	}

	return 0;
}

/* ---- 사용자 로그인 -------------------------------------------------------
 *
 * 기기 신원은 서비스가 들고 있고, 사람의 신원은 여기서 IdP 에 받아 온다 (Oidc.h).
 * 받아 온 토큰은 서비스에 건네고, 서비스가 세션 안으로 서버에 보낸다. 서버의 답(누구로
 * 로그인됐는지, 왜 거절했는지)은 WM_VPN_LOGIN 으로 돌아온다.
 *
 * 토큰은 수명이 짧다 (보통 5분). 4분의 3이 지나면 refresh token 으로 브라우저 없이 새 것을
 * 받아 다시 건넨다. refresh token 은 DPAPI 로 감싸 두어 다음에 켤 때도 이어서 로그인한다. */

struct LoginDone {
	oidc::Outcome outcome;
	bool interactive;
	unsigned gen;
};

struct LoginJob {
	oidc::Config cfg;
	std::string refresh;
	bool interactive;
	unsigned gen;
	HWND notify;
	HANDLE cancel;
};

static DWORD WINAPI LoginThread(LPVOID arg)
{
	LoginJob *job = static_cast<LoginJob *>(arg);
	LoginDone *done = new LoginDone;

	done->interactive = job->interactive;
	done->gen = job->gen;
	done->outcome = job->interactive ? oidc::Login(job->cfg, job->cancel) :
		oidc::Refresh(job->cfg, job->refresh, job->cancel);

	if (!job->refresh.empty()) {
		SecureZeroMemory(&job->refresh[0], job->refresh.size());
	}
	if (!PostMessageW(job->notify, WM_LOGIN_DONE, 0, reinterpret_cast<LPARAM>(done))) {
		oidc::Wipe(&done->outcome.tokens);
		delete done;
	}
	delete job;

	return 0;
}

/* 서버가 보내는 사용자 이름은 UTF-8 이다. CString(char *) 는 ANSI 코드페이지로 읽어 깨진다. */
static CString FromUtf8(const char *s)
{
	const int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
	CString out;

	if (n > 1) {
		MultiByteToWideChar(CP_UTF8, 0, s, -1, out.GetBuffer(n), n);
		out.ReleaseBuffer();
	}

	return out;
}

/* 리프레시 토큰을 IdP 에서 폐기하는 워커. 결과를 기다리지 않는다 (로그아웃은 이 PC 에서 이미
 * 끝났다). 창이 먼저 사라져도 되게 필요한 것을 모두 복사해 간다. */
struct RevokeJob {
	oidc::Config cfg;
	std::string refresh;
};

static DWORD WINAPI RevokeThread(LPVOID arg)
{
	RevokeJob *job = static_cast<RevokeJob *>(arg);

	oidc::Revoke(job->cfg, job->refresh);
	SecureZeroMemory(&job->refresh[0], job->refresh.size());
	delete job;

	return 0;
}

/* 서버가 토큰을 받지 않은 이유. 사용자가 할 수 있는 일이 거의 없으므로 짧게. */
static CString LoginStatusText(uint32_t status)
{
	switch (status) {
	case LOGIN_NO_IDP:	return _T("서버가 사용자 로그인을 받지 않음");
	case LOGIN_MALFORMED:	return _T("토큰의 형식이 맞지 않음");
	case LOGIN_UNTRUSTED:	return _T("서버가 이 IdP 의 서명을 믿지 않음");
	case LOGIN_WRONG_TOKEN:	return _T("다른 서비스에 발급된 토큰");
	case LOGIN_EXPIRED:	return _T("토큰이 만료됨");
	case LOGIN_BAD_USER:	return _T("쓸 수 없는 사용자 이름");
	case LOGIN_DPOP:	return _T("기기 키 증명이 없거나 틀림");
	default:		return _T("알 수 없는 이유");
	}
}

void CMainDlg::OnLogin()
{
	/* 브라우저를 기다리는 중이면 그만둔다. */
	if (m_login_thread && m_login_interactive) {
		SetEvent(m_login_cancel);
		return;
	}

	/* 갱신 워커가 돌고 있어도 로그아웃은 바로 한다. 그 워커의 결과는 세대가 바뀌어 버려진다.
	 * IdP 에 닿지 않아 갱신이 재시도를 거듭하는 중일수록 사용자는 끊고 싶어 한다. */
	if (!m_tokens.access.empty() || !m_tokens.refresh.empty() || m_login.state != IPC_LOGIN_NONE) {
		Logout(_T("[login] 로그아웃했습니다"));
		return;
	}

	StartLogin(true);
}

/* interactive: 브라우저를 띄운다. 아니면 들고 있는 refresh token 으로 조용히 받는다. */
void CMainDlg::StartLogin(bool interactive)
{
	LoginJob *job;

	if (m_login_thread || m_issuer.IsEmpty() || (!interactive && m_tokens.refresh.empty())) {
		return;
	}

	job = new LoginJob;
	job->cfg = LoginConfig();
	job->refresh = interactive ? std::string() : m_tokens.refresh;
	job->interactive = interactive;
	job->gen = m_login_gen;
	job->notify = GetSafeHwnd();
	job->cancel = m_login_cancel;

	ResetEvent(m_login_cancel);
	m_login_thread = CreateThread(nullptr, 0, LoginThread, job, 0, nullptr);
	if (!m_login_thread) {
		delete job;
		m_login_error = _T("로그인을 시작하지 못했습니다");
	}
	else {
		m_login_interactive = interactive;
		if (interactive) {
			m_login_error.Empty();
		}
		AppendLog(interactive ? _T("[login] 브라우저에서 IdP 로그인을 엽니다") : _T("[login] 토큰을 갱신합니다"));
	}

	UpdateInfo();
	UpdateLoginButton();
}

LRESULT CMainDlg::OnLoginDone(WPARAM, LPARAM lParam)
{
	LoginDone *done = reinterpret_cast<LoginDone *>(lParam);
	oidc::Outcome &o = done->outcome;
	const bool stale = done->gen != m_login_gen;

	if (m_login_thread) {
		WaitForSingleObject(m_login_thread, 1000);	/* 메시지를 보낸 뒤 곧 끝난다 */
		CloseHandle(m_login_thread);
		m_login_thread = nullptr;
	}

	/* 그사이에 로그아웃했거나 설정을 바꿨다. 늦게 온 토큰을 쓰지 않는다. */
	if (stale) {
		oidc::Wipe(&o.tokens);
		delete done;
		UpdateInfo();
		UpdateLoginButton();
		return 0;
	}

	switch (o.result) {
	case oidc::RESULT_OK: {
		CString line;

		/* 토큰은 UDP 패킷 하나에 들어가야 한다. 그룹이나 역할이 아주 많으면 넘는다 — 그때는 IdP
		 * 쪽에서 클레임을 줄여야 한다 (README "사용자 로그인"). 기다리게 두지 않고 바로 알린다. */
		if (o.tokens.access.size() > LOGIN_TOKEN_MAX) {
			line.Format(_T("토큰이 너무 큽니다 (%u / %u 바이트). 관리자에게 알려 주세요"),
					(unsigned)o.tokens.access.size(), (unsigned)LOGIN_TOKEN_MAX);
			Logout(_T("[login] ") + line);
			m_login_error = line;
			break;
		}

		oidc::Wipe(&m_tokens);
		m_tokens = o.tokens;
		if (!m_tokens.refresh.empty()) {
			oidc::SaveRefresh(LoginConfig(), m_tokens.refresh);
		}
		else {
			AppendLog(_T("[login] IdP 가 refresh token 을 주지 않았습니다. 토큰이 끝나면 다시 로그인해야 합니다 (scope 에 offline_access 가 필요한 IdP 일 수 있습니다)"));
		}
		m_login_error.Empty();
		m_expiry_stage = 0;
		ScheduleRefresh(m_tokens.expires_at);
		SendToken();

		line.Format(_T("[login] IdP 에서 토큰을 받았습니다 (%lld초 유효)"),
				m_tokens.expires_at ? m_tokens.expires_at - _time64(nullptr) : 0LL);
		AppendLog(line);
		break;
	}
	case oidc::RESULT_CANCELLED:
		AppendLog(_T("[login] 로그인을 취소했습니다"));
		break;
	case oidc::RESULT_DENIED:
		AppendLog(_T("[login] ") + o.detail);
		if (done->interactive) {
			m_login_error = _T("IdP 가 로그인을 거절했습니다");
		}
		else {
			/* refresh token 이 끝났다 (IdP 에서 로그아웃, 세션 만료). 브라우저로 다시 해야 한다. */
			Logout(CString());
			m_login_error = _T("로그인이 만료됐습니다. 다시 로그인하세요");
			TrayNotify(_T("다시 로그인하세요"), CString(_T("회사 계정 로그인이 만료됐습니다. 사용자별 접근은 다시 로그인할 때까지 닫힙니다.")), false);
		}
		break;
	case oidc::RESULT_NETWORK:
		AppendLog(_T("[login] ") + o.detail);
		if (done->interactive) {
			m_login_error = _T("IdP 에 닿지 못했습니다");
		}
		else {
			/* 들고 있는 토큰은 그대로 두고 잠시 뒤에 다시 해 본다. */
			m_refresh_at = GetTickCount64() + LOGIN_RETRY_MS;
			if (m_tokens.access.empty()) {
				m_login_error = _T("IdP 에 닿지 못했습니다. 잠시 뒤 다시 시도합니다");
			}
		}
		break;
	case oidc::RESULT_TIMEOUT:
		AppendLog(_T("[login] ") + o.detail);
		m_login_error = _T("브라우저에서 로그인을 마치지 않았습니다");
		break;
	default:
		AppendLog(_T("[login] ") + o.detail);
		if (done->interactive || m_tokens.access.empty()) {
			m_login_error = _T("로그인하지 못했습니다 (진단 창의 로그)");
		}
		if (!done->interactive) {
			m_refresh_at = GetTickCount64() + 5 * LOGIN_RETRY_MS;
		}
		break;
	}

	oidc::Wipe(&o.tokens);
	delete done;

	UpdateInfo();
	UpdateLoginButton();

	return 0;
}

/* 이 PC 에서의 로그인을 끝낸다. 저장한 refresh token 을 지우고, 서비스에 알려 서버의 세션에서도
 * 사용자를 뗀다. IdP 의 브라우저 세션은 그대로다 — 다음 로그인은 비밀번호 없이 끝날 수 있다. */
void CMainDlg::Logout(const CString &why)
{
	m_login_gen++;		/* 돌고 있는 워커의 결과는 버린다 */
	if (m_login_thread && m_login_interactive) {
		SetEvent(m_login_cancel);
	}

	/* IdP 에도 그 refresh token 을 버리라고 한다. 이 PC 에서 지우기만 하면 누가 미리 복사해
	 * 둔 것은 IdP 의 세션이 끝날 때까지 쓰인다. */
	if (!m_tokens.refresh.empty() && !m_issuer.IsEmpty()) {
		RevokeJob *job = new RevokeJob;
		HANDLE h;

		job->cfg = LoginConfig();
		job->refresh = m_tokens.refresh;
		h = CreateThread(nullptr, 0, RevokeThread, job, 0, nullptr);
		if (h) {
			CloseHandle(h);
		}
		else {
			SecureZeroMemory(&job->refresh[0], job->refresh.size());
			delete job;
		}
	}

	oidc::Wipe(&m_tokens);
	oidc::ForgetRefresh();
	m_refresh_at = 0;
	m_login_user.Empty();
	m_expired_retry = false;
	m_expiry_stage = 0;
	m_notified_login = 0;
	if (m_session) {
		vpn_remote_logout(m_session);
	}

	if (!why.IsEmpty()) {
		AppendLog(why);
	}
	UpdateInfo();
	UpdateLoginButton();
}

/* 서비스에 토큰을 건넨다. 서비스에 붙지 못했으면 붙을 때 다시 부른다 (OnVpnService). */
void CMainDlg::SendToken()
{
	if (m_tokens.access.empty() || m_link != VPN_REMOTE_UP || m_suspended) {
		return;
	}

	if (vpn_remote_login(m_session, m_tokens.access.data(), m_tokens.access.size()) < 0) {
		AppendLog(_T("[login] 서비스에 토큰을 건네지 못했습니다"));
	}
}

/* 토큰 수명의 4분의 3 이 지나면 갱신한다. 수명을 모르면 서버의 답(만료 시각)으로 정한다. */
void CMainDlg::ScheduleRefresh(__int64 expires_at)
{
	const __int64 left = expires_at - _time64(nullptr);

	if (m_tokens.refresh.empty() || expires_at == 0) {
		m_refresh_at = 0;
		return;
	}

	const __int64 wait = left * 3 / 4 > 10 ? left * 3 / 4 : 10;

	m_refresh_at = GetTickCount64() + (ULONGLONG)wait * 1000;
}

/* 서버가 토큰에 답했다 (또는 서비스의 로그인 상태가 바뀌었다). */
LRESULT CMainDlg::OnVpnLogin(WPARAM, LPARAM)
{
	ipc_login_t now;

	vpn_remote_login_info(m_session, &now);

	if (now.state == IPC_LOGIN_DONE &&
			(m_login.state != IPC_LOGIN_DONE || m_login.status != now.status ||
			 strcmp(m_login.user, now.user) != 0 || m_login.expires != now.expires)) {
		CString line;

		if (now.status == LOGIN_OK) {
			line.Format(_T("[login] 서버: %s 로 로그인됨"), (LPCTSTR)FromUtf8(now.user));
		}
		else {
			line = _T("[login] 서버가 토큰을 받지 않음: ") + LoginStatusText(now.status);
		}
		AppendLog(line);
	}
	m_login = now;

	/* 갱신한 토큰을 건넬 때마다 서비스는 "서버의 답을 기다림"으로 돌아간다. 그동안에도 앞서
	 * 확인된 사용자를 보여 준다 — 몇 분마다 줄이 깜빡이지 않게. */
	if (now.state == IPC_LOGIN_DONE) {
		m_login_user = now.status == LOGIN_OK ? FromUtf8(now.user) : CString();
	}
	else if (now.state == IPC_LOGIN_NONE) {
		m_login_user.Empty();
	}

	if (now.state == IPC_LOGIN_DONE) {
		if (now.status == LOGIN_OK && m_tokens.expires_at == 0 && m_refresh_at == 0) {
			ScheduleRefresh(now.expires);
		}
		if (now.status == LOGIN_OK) {
			m_expired_retry = false;
			m_notified_login = 0;
		}
		/* 갱신이 늦었다. 지금 바로 받아 온다. 새 토큰도 만료라고 하면 PC 와 서버(또는 IdP)의
		 * 시계가 어긋난 것이다 — 갱신을 거듭해 IdP 를 두드리지 않고 멈춰서 알린다. */
		else if (now.status == LOGIN_EXPIRED && !m_login_thread && !m_expired_retry && !m_tokens.refresh.empty()) {
			m_expired_retry = true;
			StartLogin(false);
		}
		/* 서버에 사용자 로그인이 없다. 고칠 것이 없으므로 갱신도, 경고도 하지 않는다. */
		else if (now.status == LOGIN_NO_IDP) {
			m_refresh_at = 0;
		}
		else if (m_notified_login != now.status + 1) {
			m_notified_login = now.status + 1;
			TrayNotify(_T("사용자 로그인이 거절됐습니다"),
					LoginStatusText(now.status) + (now.status == LOGIN_EXPIRED ?
						CString(_T(". PC 의 시계가 맞는지 확인하고, 그대로면 관리자에게 알려 주세요.")) :
						CString(_T(". 관리자에게 알려 주세요."))), true);
		}
	}

	UpdateInfo();
	UpdateLoginButton();

	return 0;
}

/* 연결 정보 판의 사용자 줄. */
HomeRow CMainDlg::LoginRow() const
{
	HomeRow row;

	row.name = m_info[INFO_USER].name;
	row.level = LEVEL_NONE;

	if (m_issuer.IsEmpty()) {
		row.value = _T("사용하지 않음");
	}
	else if (m_login_thread && m_login_interactive) {
		row.value = _T("브라우저에서 로그인하세요\x2026");
	}
	else if (m_tokens.access.empty()) {
		if (m_login_thread) {
			row.value = _T("로그인 중\x2026");
		}
		else if (!m_login_error.IsEmpty()) {
			row.value = m_login_error;
			row.level = LEVEL_BAD;
		}
		else {
			row.value = _T("로그인하지 않음");
		}
	}
	else if (m_tokens.expires_at != 0 && _time64(nullptr) >= m_tokens.expires_at) {
		/* 갱신하지 못한 채 끝났다. 서버도 사용자를 뗐다. */
		row.value = m_tokens.refresh.empty() ? _T("로그인이 끝남 \x2014 다시 로그인하세요") : _T("로그인이 끝남 \x2014 갱신을 다시 시도하는 중");
		row.level = LEVEL_BAD;
	}
	else if (m_suspended) {
		row.value = _T("이 화면이 잠시 떨어져 쉬는 중");
	}
	else if (m_link != VPN_REMOTE_UP || m_login.state == IPC_LOGIN_NONE) {
		row.value = _T("서비스에 건네는 중\x2026");
	}
	else if (m_login.state == IPC_LOGIN_PENDING && !m_login_user.IsEmpty()) {
		row.value = m_login_user;
		row.level = LEVEL_OK;
	}
	else if (m_login.state == IPC_LOGIN_PENDING) {
		row.value = (m_state == TUNNEL_STATE_CONNECTED) ? _T("서버가 확인하는 중\x2026") : _T("연결하면 서버에 알립니다");
	}
	else if (m_login.status == LOGIN_OK) {
		row.value = FromUtf8(m_login.user);
		row.level = LEVEL_OK;
	}
	else if (m_login.status == LOGIN_NO_IDP) {
		row.value = LoginStatusText(m_login.status);	/* 잘못된 것이 아니다. 붉게 칠하지 않는다 */
	}
	else {
		row.value = LoginStatusText(m_login.status);
		row.level = LEVEL_BAD;
	}

	return row;
}

void CMainDlg::UpdateLoginButton()
{
	CWnd *btn = GetDlgItem(IDC_LOGIN);
	CString text;
	BOOL enable = TRUE;

	if (!btn) {
		return;
	}

	if (m_login_thread && m_login_interactive) {
		text = _T("취소");
	}
	else if (!m_tokens.access.empty() || m_login.state != IPC_LOGIN_NONE) {
		text = _T("로그아웃");
	}
	else {
		text = _T("로그인");
		enable = m_login_thread == nullptr;	/* 갱신하는 중에는 기다린다 */
	}

	CString old;
	btn->GetWindowText(old);
	if (old != text) {
		btn->SetWindowText(text);
	}
	btn->EnableWindow(enable);
}

oidc::Config CMainDlg::LoginConfig() const
{
	oidc::Config cfg;

	cfg.issuer = m_issuer;
	cfg.client_id = m_client_id;
	cfg.scope = m_scope;
	/* 로그인 스레드에서 불린다. 서비스와의 연결(m_session)은 여러 스레드에서 써도 된다. */
	vpn_session_t *session = m_session;
	cfg.dpop = [session](const std::string &htu, std::string *proof) {
		char buf[1024];

		if (vpn_remote_dpop(session, htu.c_str(), buf, sizeof(buf)) != 0) {
			return false;
		}
		*proof = buf;
		return true;
	};

	return cfg;
}

/* 토큰이 곧 끝나거나 끝났는데 새 것을 받지 못했다. 사용자별 접근이 닫히므로 알린다.
 * refresh token 이 없는 IdP 는 1분 전에 미리 알린다 (다시 로그인할 틈을 준다). */
void CMainDlg::CheckLoginExpiry()
{
	const __int64 now = _time64(nullptr);

	if (m_tokens.access.empty() || m_tokens.expires_at == 0) {
		return;
	}

	if (now >= m_tokens.expires_at && m_expiry_stage < 2) {
		m_expiry_stage = 2;
		TrayNotify(_T("사용자 로그인이 끝났습니다"),
				m_tokens.refresh.empty() ?
				CString(_T("사용자별 접근이 닫혔습니다. ztgate 에서 다시 로그인하세요.")) :
				CString(_T("IdP 에 닿지 못해 로그인을 이어 가지 못했습니다. 닿는 대로 다시 시도합니다.")), true);
		UpdateInfo();
	}
	else if (m_tokens.refresh.empty() && now >= m_tokens.expires_at - 60 && m_expiry_stage < 1) {
		m_expiry_stage = 1;
		TrayNotify(_T("곧 로그인이 끝납니다"),
				CString(_T("1분 뒤 사용자별 접근이 닫힙니다. 계속 쓰려면 ztgate 에서 로그아웃한 뒤 다시 로그인하세요.")), false);
	}
}

/* 이 Windows 세션이 화면에서 떨어지거나(사용자 전환, 원격 연결 끊김) 로그오프하면 서비스에서
 * 토큰을 뺀다. 터널은 PC 하나에 하나라, 그대로 두면 다음에 화면 앞에 앉은 사람의 트래픽이
 * 이 사람의 신원으로 나간다. 돌아오면 다시 건넨다 (끝났으면 갱신한다). */
LRESULT CMainDlg::OnSessionChange(WPARAM wParam, LPARAM)
{
	switch (wParam) {
	case WTS_CONSOLE_DISCONNECT:
	case WTS_REMOTE_DISCONNECT:
	case WTS_SESSION_LOGOFF:
		if (!m_suspended) {
			m_suspended = true;
			if (m_session) {
				vpn_remote_logout(m_session);
			}
			AppendLog(_T("[login] 이 세션이 화면에서 떨어져 사용자 신원을 서비스에서 뺐습니다"));
		}
		break;
	case WTS_CONSOLE_CONNECT:
	case WTS_REMOTE_CONNECT:
		if (m_suspended) {
			m_suspended = false;
			AppendLog(_T("[login] 이 세션으로 돌아왔습니다"));
			if (m_tokens.expires_at != 0 && _time64(nullptr) >= m_tokens.expires_at - 30 && !m_login_thread) {
				StartLogin(false);
			}
			else {
				SendToken();
			}
		}
		break;
	default:
		break;
	}

	UpdateInfo();
	UpdateLoginButton();

	return 0;
}

/* 패킷 이벤트에서 "무엇을 보고했고 서버가 뭐라고 했는지"를 주워 둔다.
 * 코어에 콜백을 더 만들지 않았다. 필요한 사실이 이미 패킷으로 올라온다. */
void CMainDlg::TrackAuth(const tunnel_packet_t &p)
{
	if (p.dir != TUNNEL_DIR_RX || p.verdict != TUNNEL_PASS) {
		return;
	}

	/* 서버가 정해 준 터널 주소. 수락과 keepalive 응답에 실려 온다. 관리자가 도중에
	 * 바꾸면 여기도 따라 바뀐다. 같은 값으로 다시 쓰지 않는다 — 10초마다 깜빡인다. */
	if (p.has_netcfg) {
		wchar_t ip[INET_ADDRSTRLEN];
		CString text;

		if (InetNtopW(AF_INET, &p.cfg_tun_ip, ip, INET_ADDRSTRLEN) != NULL) {
			if (p.cfg_routes != 0) {
				text.Format(_T("%s/%u  +경로 %u"), ip, (unsigned)p.cfg_prefix_len, (unsigned)p.cfg_routes);
			}
			else {
				text.Format(_T("%s/%u"), ip, (unsigned)p.cfg_prefix_len);
			}
			if (text != m_tun_text) {
				m_tun_text = text;
				UpdateInfo();
			}
		}
	}

	if (p.msg_type == MSG_TYPE_DENY || p.msg_type == MSG_TYPE_VERSION) {
		m_deny_reason = p.deny_reason;
	}
	else if (p.msg_type == MSG_TYPE_RES_HANDSHAKE) {
		m_deny_reason = 0;
		m_session_idx = p.session_idx;
	}
}

CString CMainDlg::LocalStateName(int state)
{
	switch (state) {
	case POSTURE_ON:	return _T("켜짐");
	case POSTURE_OFF:	return _T("꺼짐");
	default:		return _T("확인 불가");
	}
}

/* collect 가 true 면 이 PC 의 상태를 다시 읽는다. 수십 ms 걸리는 호출이라 패킷이
 * 올 때마다 하지 않고 타이머에서만 한다.
 *
 * 이 PC 의 값만 보고 "충족 / 미달"을 매기지 않는다. 서버가 무엇을 요구하는지 클라이언트는
 * 모른다 — 백신이 꺼져 있어도 정책이 요구하지 않으면 접속된다. 그래서 켜짐은 초록, 꺼짐은
 * 빨강으로 상태만 보이고, 접속이 되는지는 "서버 판정" 줄이 따로 말한다. */
void CMainDlg::RefreshPosture(bool collect)
{
	HomeRow rows[CHECK_COUNT];
	CString s;

	if (collect) {
		posture_collect(&m_local);
	}

	for (int i = 0; i < CHECK_COUNT; i++) {
		rows[i].name = m_checks[i].name;
	}

	rows[CHECK_FIREWALL].value = LocalStateName(m_local.firewall);
	rows[CHECK_FIREWALL].level = m_local.firewall == POSTURE_ON ? LEVEL_OK :
			m_local.firewall == POSTURE_OFF ? LEVEL_BAD : LEVEL_NONE;
	rows[CHECK_ANTIVIRUS].value = LocalStateName(m_local.antivirus);
	rows[CHECK_ANTIVIRUS].level = m_local.antivirus == POSTURE_ON ? LEVEL_OK :
			m_local.antivirus == POSTURE_OFF ? LEVEL_BAD : LEVEL_NONE;
	rows[CHECK_DISK].value = LocalStateName(m_local.disk);
	rows[CHECK_DISK].level = m_local.disk == POSTURE_ON ? LEVEL_OK :
			m_local.disk == POSTURE_OFF ? LEVEL_BAD : LEVEL_NONE;

	if (m_local.os_build != 0) {
		s.Format(_T("%u.%u.%u"), m_local.os_major, m_local.os_minor, m_local.os_build);
		rows[CHECK_OS].level = LEVEL_OK;
	}
	else {
		s = _T("확인 불가");
		rows[CHECK_OS].level = LEVEL_NONE;
	}
	rows[CHECK_OS].value = s;

	if (m_deny_reason != 0) {
		/* 사유는 상태 판에 있다. 여기에 또 적으면 판의 폭을 넘어 잘린다. */
		rows[CHECK_SERVER].value = _T("차단됨");
		rows[CHECK_SERVER].level = LEVEL_BAD;
	}
	else if (m_state == TUNNEL_STATE_CONNECTED) {
		rows[CHECK_SERVER].value = _T("접속 허용");
		rows[CHECK_SERVER].level = LEVEL_OK;
	}
	else if (m_state == TUNNEL_STATE_DENIED) {
		rows[CHECK_SERVER].value = _T("차단");
		rows[CHECK_SERVER].level = LEVEL_BAD;
	}
	else {
		rows[CHECK_SERVER].value = m_state == TUNNEL_STATE_STOPPED ? _T("연결하면 확인") : _T("확인 중");
		rows[CHECK_SERVER].level = LEVEL_NONE;
	}

	/* 바뀐 것이 있을 때만 그 판을 다시 그린다. 2초마다 같은 것을 그리면 깜빡일 틈을 준다. */
	bool changed = false;

	for (int i = 0; i < CHECK_COUNT; i++) {
		if (rows[i].value != m_checks[i].value || rows[i].level != m_checks[i].level) {
			m_checks[i] = rows[i];
			changed = true;
		}
	}
	if (changed && !m_rc_security.IsRectEmpty()) {
		InvalidateRect(&m_rc_security, FALSE);
	}
}

/* ---- 진단 창 ----------------------------------------------------------- */
void CMainDlg::OnDiag()
{
	m_diag.Open(this);
}

/* 로그는 진단 창이 닫혀 있어도 여기에 쌓는다. 무엇이 잘못됐는지 보려고 진단 창을
 * 여는 것은 대개 일이 벌어진 뒤다. */
void CMainDlg::AppendLog(const CString &text)
{
	m_logLines.push_back(text);
	while (m_logLines.size() > LOG_MAX_LINES) {
		m_logLines.pop_front();
	}

	m_diag.LogAppended(text);
}

/* ---- 상태 -------------------------------------------------------------- */

void CMainDlg::SetUiState(tunnel_state_t state)
{
	BOOL stopped;
	CWnd *connect = GetDlgItem(IDC_CONNECT);
	const tunnel_state_t prev = m_state;
	const bool userStop = m_stopping;	/* 아래에서 지우기 전에 */

	/* 연결된 때는 서비스가 안다. 이 창을 나중에 켜도 터널이 연결된 때부터 센다. */
	if (state == TUNNEL_STATE_CONNECTED) {
		const ULONGLONG since = vpn_remote_connected_since(m_session);

		if (since != 0) {
			m_connected_at = since;
		}
		else if (m_connected_at == 0) {
			m_connected_at = GetTickCount64();
		}
	}
	else if (state == TUNNEL_STATE_DENIED) {
		m_connected_at = 0;
	}
	else if (state == TUNNEL_STATE_STOPPED) {
		m_connected_at = 0;
		m_session_idx = 0;
		m_stopping = false;
	}

	m_state = state;
	UpdateStatus();
	RefreshPosture(false);
	if (prev != state) {
		NotifyTransition(prev, state, userStop);
	}

	stopped = (state == TUNNEL_STATE_STOPPED) ? TRUE : FALSE;

	/* 강조색 버튼은 "지금 할 일"에만 쓴다. 연결된 뒤의 해제는 흔한 동작이 아니므로
	 * 보조 버튼으로 물러난다. */
	/* AlwaysOn 이면 서비스가 해제를 받지 않는다. 눌러서 거절당하게 두지 않고 처음부터 막는다. */
	const bool locked = !stopped && m_policy.always_on;

	connect->SetWindowText(stopped ? _T("연결") : m_stopping ? _T("해제 중…") :
			locked ? _T("회사 정책으로 늘 연결") : _T("연결 해제"));
	connect->EnableWindow(!m_stopping && !locked);
	ui::SetButtonKind(connect->GetSafeHwnd(), stopped ? ui::BUTTON_PRIMARY : ui::BUTTON_SECONDARY);
	connect->Invalidate(FALSE);

	/* Enter 는 다이얼로그의 기본 버튼으로 간다. 닫혀 있을 때는 그것이 [연결]이라 편하지만,
	 * 열려 있을 때는 같은 버튼이 [연결 해제]다 — 창을 앞으로 가져오며 Enter 를 눌렀다고
	 * 터널이 끊겨서는 안 된다. 그동안은 기본 버튼을 없는 컨트롤로 돌려 둔다 (그쪽으로
	 * 가는 BN_CLICKED 는 받는 곳이 없다). */
	SendMessage(DM_SETDEFID, stopped ? IDC_CONNECT : IDC_NO_DEFAULT);

	/* 터널이 닫히면 받았던 주소도 더는 내 것이 아니다. */
	if (stopped && !m_tun_text.IsEmpty()) {
		m_tun_text.Empty();
		UpdateInfo();
	}
}

static CString BytesText(ULONGLONG bytes)
{
	CString s;

	if (bytes < 1024) {
		s.Format(_T("%llu B"), bytes);
	}
	else if (bytes < 1024 * 1024) {
		s.Format(_T("%.1f KB"), (double)bytes / 1024.0);
	}
	else {
		s.Format(_T("%.1f MB"), (double)bytes / (1024.0 * 1024.0));
	}

	return s;
}

/* 연결 정보 판: 어느 서버로 붙는지, 서버가 배정한 터널 주소, 주고받은 양, 이 기기.
 * 보는 칸이다 — 서버 주소는 설정 창에서 바꾸고, 터널 주소는 서버가 정해 준다. */
void CMainDlg::UpdateInfo()
{
	const PacketStats &st = m_store.Stats();
	HomeRow rows[INFO_COUNT];

	for (int i = 0; i < INFO_COUNT; i++) {
		rows[i].name = m_info[i].name;
		rows[i].level = LEVEL_NONE;
	}

	rows[INFO_USER] = LoginRow();
	rows[INFO_SERVER].value = m_server.IsEmpty() ? CString(_T("정해지지 않음")) : m_server + _T(" : ") + m_port;
	rows[INFO_TUNNEL].value = m_tun_text.IsEmpty() ? CString(_T("연결하면 서버가 배정")) : m_tun_text;
	/* 화살표(U+2191 / 2193)는 글꼴 대체로 컬러 이모지가 되어 혼자 튄다. 글자로 적는다. */
	rows[INFO_TRAFFIC].value = _T("보냄 ") + BytesText(st.tx_bytes) + _T("   \x00b7   받음 ") + BytesText(st.rx_bytes);

	/* ID 는 32자라 판에 다 들어가지 않는다. 앞 12자면 서버의 기기 목록에서 찾기에 충분하다.
	 * 전체는 진단 창의 로그에 있다. */
	if (m_device_id.IsEmpty()) {
		rows[INFO_DEVICE].value = _T("등록되지 않음");
		rows[INFO_DEVICE].level = LEVEL_BAD;
	}
	else {
		rows[INFO_DEVICE].value = m_device_id.Left(12) + _T("\x2026");
	}

	/* 이미 등록된 PC 에서 "기기 등록"이 파란 링크로 서 있으면 아직 할 일이 남은 것처럼
	 * 읽힌다. 하는 일(새 코드로 신원을 바꾸기)에 맞게 부른다. */
	CString enrollText = m_device_id.IsEmpty() ? _T("기기 등록") : _T("다시 등록");
	CString shown;
	GetDlgItemText(IDC_ENROLL, shown);
	if (shown != enrollText) {
		SetDlgItemText(IDC_ENROLL, enrollText);
	}

	bool changed = false;

	for (int i = 0; i < INFO_COUNT; i++) {
		if (rows[i].value != m_info[i].value || rows[i].level != m_info[i].level) {
			m_info[i] = rows[i];
			changed = true;
		}
	}
	if (changed && !m_rc_conn.IsRectEmpty()) {
		InvalidateRect(&m_rc_conn, FALSE);
	}
}

/* 거부됐을 때 사용자가 할 수 있는 일. 서버는 사유의 종류만 알려 준다 — 포스처 중 무엇이
 * 모자랐는지는 말하지 않는다 (정책을 밖에 드러내지 않는다). 그래서 이 PC 에서 꺼져 있는
 * 것을 먼저 가리키고, 다 켜져 있으면 관리자에게 넘긴다. */
CString CMainDlg::DenyHint() const
{
	switch (m_deny_reason) {
	case DENY_POSTURE:
		if (m_local.firewall == POSTURE_OFF) {
			return _T("Windows 방화벽이 꺼져 있습니다. 켜면 자동으로 다시 연결됩니다.");
		}
		if (m_local.antivirus == POSTURE_OFF) {
			return _T("백신의 실시간 보호가 꺼져 있습니다. 켜면 자동으로 다시 연결됩니다.");
		}
		if (m_local.disk == POSTURE_OFF) {
			return _T("시스템 드라이브의 BitLocker 가 꺼져 있습니다. 켜면 자동으로 다시 연결됩니다.");
		}
		return _T("이 PC 가 회사 보안 정책에 맞지 않습니다. 관리자에게 문의하세요.");
	case DENY_UNKNOWN_DEVICE:
		return _T("서버에 이 기기가 없습니다. 관리자에게 새 등록 코드를 받아 아래 [다시 등록] 을 해 주세요.");
	case DENY_BAD_AUTH:
		return _T("기기 인증에 실패했습니다. 새 등록 코드로 [다시 등록] 해야 할 수 있습니다. 관리자에게 문의하세요.");
	case DENY_TUN_IP:
		return _T("서버의 기기 설정이 맞지 않습니다. 관리자에게 문의하세요.");
	case TUNNEL_DENY_CLIENT_OLD:
		/* 자동 업데이트는 정책에 매니페스트 주소가 있을 때만 돈다 (svc update_tick). */
		if (m_policy.update_url[0] != L'\0') {
			return _T("서버가 이 프로그램보다 새 버전입니다. 업데이트를 확인하는 중입니다. 계속되면 관리자에게 새 버전을 받아 주세요.");
		}
		return _T("서버가 이 프로그램보다 새 버전입니다. 관리자에게 새 버전을 받아 설치해 주세요.");
	case TUNNEL_DENY_SERVER_OLD:
		return _T("서버가 이 프로그램보다 오래된 버전입니다. 관리자에게 서버 업데이트를 요청하세요.");
	default:
		return _T("관리자에게 문의하세요.");
	}
}

/* 상태 판의 글과 색을 지금 값으로 다시 정한다. 바뀐 것이 있을 때만 그 영역을 다시
 * 그린다 — 500ms 마다 불리므로 매번 그리면 쓸데없이 깜빡일 틈을 준다. */
void CMainDlg::UpdateStatus()
{
	const ui::Palette &c = ui::Colors();
	CString title;
	CString sub;
	CString hint;
	LPCWSTR icon = ICON_POWER;
	COLORREF color = c.idle;
	COLORREF hintColor = c.danger;

	switch (m_state) {
	case TUNNEL_STATE_CONNECTING:
		title = _T("연결 중");
		sub = _T("서버에 이 기기를 인증하고 있습니다");
		icon = ICON_SYNC;
		color = c.warn;
		break;
	case TUNNEL_STATE_CONNECTED:
		title = _T("연결됨");
		sub = _T("사내망에 안전하게 연결됐습니다");
		if (m_connected_at) {
			ULONGLONG sec = (GetTickCount64() - m_connected_at) / 1000;
			CString t;

			t.Format(_T("   \x00b7   %02llu:%02llu:%02llu"), sec / 3600, (sec / 60) % 60, sec % 60);
			sub += t;
		}
		icon = ICON_CHECK;
		color = c.ok;
		/* 차단 안내가 들어갈 자리가 평소에는 비어 있다. 처음 쓰는 사람이 가장 많이 묻는
		 * 것("창을 닫으면 끊기나")을 흐리게 둔다. */
		hint = _T("창을 닫아도 연결은 유지됩니다. 알림 영역의 아이콘으로 다시 열 수 있습니다.");
		hintColor = c.muted;
		break;
	case TUNNEL_STATE_RECONNECTING:
		title = _T("다시 연결 중");
		sub = _T("서버의 응답이 없어 세션을 다시 맺고 있습니다");
		icon = ICON_SYNC;
		color = c.warn;
		break;
	}

	/* 서버에 닿지 못하는 까닭이 이 PC 쪽 네트워크라면 그것을 먼저 말한다. */
	if ((m_state == TUNNEL_STATE_CONNECTING || m_state == TUNNEL_STATE_RECONNECTING) && m_deny_reason == 0) {
		if (m_portal == portal::CAPTIVE) {
			sub = _T("이 네트워크는 로그인해야 인터넷을 쓸 수 있습니다");
			hint = _T("호텔·카페 와이파이처럼 로그인 페이지가 있는 망입니다. 여기를 누르면 로그인 페이지가 열리고, 로그인하면 자동으로 연결됩니다.");
			/* 차단을 풀지는 않는다. 끊긴 동안 내부망을 막는 것이 그 정책의 뜻이다. */
			if (m_policy.block_when_down) {
				hint = _T("로그인 페이지가 있는 망입니다. 여기를 누르면 로그인 페이지가 열립니다. 회사 정책이 연결 전의 내부망 접속을 막고 있어 페이지가 열리지 않으면 IT 담당자에게 문의하세요.");
			}
			hintColor = c.warn;
		}
		else if (m_portal == portal::OFFLINE) {
			sub = _T("인터넷에 연결되어 있지 않습니다");
			hint = _T("와이파이나 랜선 연결을 확인하세요. 네트워크가 돌아오면 자동으로 연결됩니다.");
			hintColor = c.muted;
		}
	}
	/* 서비스는 연결을 원하지만(AlwaysOn) 이 PC 에 신원이 없어 터널을 올리지 못하고 기다린다.
	 * "다시 연결 중"으로 두면 서버를 탓하게 된다. */
	if ((m_state == TUNNEL_STATE_CONNECTING || m_state == TUNNEL_STATE_RECONNECTING) &&
			m_link == VPN_REMOTE_UP && m_device_known && m_device_id.IsEmpty() && !vpn_remote_running(m_session)) {
		title = _T("등록 필요");
		sub = _T("이 PC 는 아직 등록되지 않았습니다");
		hint = _T("아래 [기기 등록] 에 관리자에게 받은 초대 링크나 코드를 넣어 주세요. 등록되면 자동으로 연결됩니다.");
		hintColor = c.warn;
		icon = ICON_WARNING;
		color = c.warn;
	}
	switch (m_state) {
	case TUNNEL_STATE_CONNECTING:
	case TUNNEL_STATE_CONNECTED:
	case TUNNEL_STATE_RECONNECTING:
		break;	/* 위에서 정했다 */
	case TUNNEL_STATE_DENIED:
		title = _T("접속 차단됨");
		sub = _T("서버가 이 기기의 접속을 막았습니다");
		icon = ICON_CROSS;
		color = c.danger;
		break;
	case TUNNEL_STATE_STOPPED:
	default:
		title = _T("연결되지 않음");
		sub = _T("연결을 누르면 사내망에 연결됩니다");
		icon = ICON_POWER;
		color = c.idle;

		/* 서비스에 붙지 못했으면 연결을 눌러도 아무 일도 일어나지 않는다. 그 이유가
		 * 가장 먼저 보여야 한다. */
		if (m_link == VPN_REMOTE_MISMATCH) {
			hint = _T("서비스와 이 프로그램의 버전이 다릅니다. 알림 영역의 ztgate 아이콘을 오른쪽 클릭해 [종료] 한 뒤 ztgate 를 다시 시작하세요. 계속되면 다시 설치하세요.");
		}
		else if (m_link == VPN_REMOTE_BUSY) {
			hint = _T("다른 프로그램이 서비스에 붙어 있습니다. 다른 Windows 사용자의 ztgate 일 수 있습니다 (사용자 전환, 원격 데스크톱). 이 창이 하나 더 떠 있는지도 확인하세요.");
		}
		else if (m_link != VPN_REMOTE_UP) {
			hint = _T("터널을 맡는 ztgate 서비스가 돌고 있지 않습니다. PC 를 다시 시작하거나 ztgate 를 다시 설치해 보세요.");
		}
		else if (m_server.IsEmpty()) {
			hint = _T("연결할 서버가 아직 정해지지 않았습니다. 아래 [기기 등록] 에 관리자에게 받은 초대 링크를 붙여 넣거나 [설정] 에서 서버를 적어 주세요.");
			hintColor = c.muted;
		}
		else if (m_device_id.IsEmpty()) {
			hint = _T("이 PC 는 아직 등록되지 않았습니다. 아래 [기기 등록] 에 관리자에게 받은 코드를 넣어 주세요.");
			hintColor = c.muted;
		}
		break;
	}

	/* 거부됐으면 사유와 할 일을 둔다. 연결이 끊긴 뒤에도 남겨 둔다 — 첫 핸드셰이크에서
	 * 거부되면 곧바로 닫히므로, 지우면 사유를 볼 틈이 없다. 거부된 채 기다리는 동안
	 * 클라이언트는 포스처가 바뀌면 스스로 다시 시도한다. */
	if (m_deny_reason != 0) {
		title = _T("접속 차단됨");
		sub = _T("사유: ") + pkt::DenyReasonName(m_deny_reason);
		hint = DenyHint();
		hintColor = c.danger;
		icon = (m_state == TUNNEL_STATE_STOPPED) ? ICON_WARNING : ICON_CROSS;
		color = c.danger;
	}

	if (m_stopping) {
		title = _T("해제 중");
		sub = _T("터널을 닫고 어댑터를 정리하고 있습니다");
		hint.Empty();
		icon = ICON_SYNC;
		color = c.idle;
	}

	if (title == m_status_title && sub == m_status_sub && hint == m_status_hint &&
			icon == m_status_icon && color == m_status_color && hintColor == m_status_hint_color) {
		return;
	}

	m_status_title = title;
	m_status_sub = sub;
	m_status_hint = hint;
	m_status_icon = icon;
	m_status_color = color;
	m_status_hint_color = hintColor;

	if (!m_rc_hero_text.IsRectEmpty()) {
		InvalidateRect(&m_rc_hero_text, FALSE);
	}
	TrayTip(_T("ztgate \x2014 ") + title);
}

void CMainDlg::OnTimer(UINT_PTR id)
{
	if (id == TIMER_TICK_ID) {
		UpdateStatus();		/* 경과 시간 */
		UpdateInfo();		/* 주고받은 양 */

		if (++m_posture_ticks >= POSTURE_REFRESH_TICKS) {
			m_posture_ticks = 0;
			RefreshPosture(true);
			UpdateStatus();	/* 거부 안내는 지금 꺼져 있는 것을 가리킨다 */
		}

		CheckLoginExpiry();
		CheckPortal();

		if (++m_policy_ticks >= POLICY_REFRESH_TICKS) {
			m_policy_ticks = 0;
			ReloadPolicy();
		}

		/* 초대 링크로 떴는데 서비스에 붙지 못한다. 기다리게만 두지 않고 까닭을 알린다. */
		if (!m_invite.IsEmpty() && m_invite_at != 0 && m_link != VPN_REMOTE_UP && !m_enrolling &&
				GetTickCount64() - m_invite_at > INVITE_WAIT_MS) {
			m_invite.Empty();
			m_invite_at = 0;
			ServiceReady();
		}

		/* 토큰이 끝나기 전에 refresh token 으로 새 것을 받아 온다. */
		if (m_refresh_at != 0 && GetTickCount64() >= m_refresh_at && !m_login_thread) {
			m_refresh_at = 0;
			StartLogin(false);
		}
	}

	CDialogEx::OnTimer(id);
}

/* ---- 그리기 ------------------------------------------------------------ */

/* 라벨과 체크 상자, 읽기 전용 편집창은 스스로 그리되 바탕색을 부모에게 묻는다. 모두
 * 흰 판 위에 있으므로 판의 색을 준다. 다이얼로그의 회색이 글자 뒤에 네모로 남지 않는다. */
HBRUSH CMainDlg::OnCtlColor(CDC *pDC, CWnd *pWnd, UINT type)
{
	const ui::Palette &c = ui::Colors();

	if (type == CTLCOLOR_STATIC || type == CTLCOLOR_BTN) {
		pDC->SetBkColor(c.card);
		pDC->SetTextColor(c.text);

		return static_cast<HBRUSH>(m_card_brush.GetSafeHandle());
	}

	return CDialogEx::OnCtlColor(pDC, pWnd, type);
}

/* 바탕은 OnPaint 가 한 번에 그린다. 여기서 먼저 지우면 지운 색이 잠깐 보인다. */
BOOL CMainDlg::OnEraseBkgnd(CDC *)
{
	return TRUE;
}

/* 테마가 입혀진 체크 상자 같은 컨트롤은 자기 뒤의 바탕을 부모에게 그려 달라고 한다
 * (DrawThemeParentBackground 가 WM_PRINTCLIENT 를 보낸다). 여기서 판을 그려 주지 않으면
 * 그 자리가 다이얼로그의 기본 회색으로 남는다. */
LRESULT CMainDlg::OnPrintClient(WPARAM wParam, LPARAM)
{
	PaintBackground(reinterpret_cast<HDC>(wParam));

	return 0;
}

void CMainDlg::OnPaint()
{
	CPaintDC paint(this);
	CRect client;
	HDC dc;
	HBITMAP bitmap;
	HGDIOBJ old;

	GetClientRect(&client);
	if (client.IsRectEmpty()) {
		return;
	}

	/* 화면 밖 비트맵에 다 그린 뒤 한 번에 옮긴다. 경과 시간과 통계가 초마다 바뀌는데
	 * 바로 그리면 지우고 쓰는 사이가 깜빡임으로 보인다. 컨트롤이 있는 자리는
	 * WS_CLIPCHILDREN 덕에 덮이지 않는다. */
	dc = CreateCompatibleDC(paint.GetSafeHdc());
	bitmap = CreateCompatibleBitmap(paint.GetSafeHdc(), client.Width(), client.Height());
	if (!dc || !bitmap) {
		PaintBackground(paint.GetSafeHdc());
	}
	else {
		old = SelectObject(dc, bitmap);
		PaintBackground(dc);
		BitBlt(paint.GetSafeHdc(), 0, 0, client.Width(), client.Height(), dc, 0, 0, SRCCOPY);
		SelectObject(dc, old);
	}

	if (bitmap) {
		DeleteObject(bitmap);
	}
	if (dc) {
		DeleteDC(dc);
	}
}

/* a 와 b 를 섞는다. t 는 a 쪽 비율(0..100). 상태 원 둘레의 옅은 띠에 쓴다. */
static COLORREF Blend(COLORREF a, COLORREF b, int t)
{
	return RGB((GetRValue(a) * t + GetRValue(b) * (100 - t)) / 100,
			(GetGValue(a) * t + GetGValue(b) * (100 - t)) / 100,
			(GetBValue(a) * t + GetBValue(b) * (100 - t)) / 100);
}

/* 판 하나: 제목과 "이름 ... 값" 줄들. 보안 상태 판은 줄 앞에 판정 기호를 단다. */
void CMainDlg::PaintCard(HDC dc, const CRect &card, LPCTSTR title, const HomeRow *rows, int count)
{
	const ui::Palette &c = ui::Colors();
	const bool icons = (rows == m_checks);
	const int pad = ui::Scale(HOME_PAD);
	const int rowH = ui::Scale(HOME_ROW_H);
	CRect rc;

	ui::RoundRect(dc, card, ui::Scale(10), c.card, c.border);

	rc.SetRect(card.left + pad, card.top, card.right - pad, card.top + ui::Scale(HOME_CARD_TITLE_H));
	ui::Text(dc, rc, title, m_fonts.strong, c.muted, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

	for (int i = 0; i < count; i++) {
		const HomeRow &row = rows[i];
		const int top = card.top + ui::Scale(HOME_CARD_TITLE_H) + i * rowH;
		int x = card.left + pad;

		/* 줄 사이의 가는 선. 첫 줄 위에는 제목과의 경계로 하나 더. */
		{
			RECT line = { x, top, card.right - pad, top + 1 };
			HBRUSH b = CreateSolidBrush(c.border);

			FillRect(dc, &line, b);
			DeleteObject(b);
		}

		if (icons) {
			const int r = ui::Scale(9);
			const int cy = top + rowH / 2;
			COLORREF fill = row.level == LEVEL_OK ? c.ok : row.level == LEVEL_BAD ? c.danger : c.idle;
			LPCWSTR glyph = row.level == LEVEL_OK ? ICON_CHECK : row.level == LEVEL_BAD ? ICON_CROSS : ICON_UNKNOWN;
			CRect g(x, cy - r, x + 2 * r, cy + r);

			ui::Dot(dc, x + r, cy, r, fill);
			ui::Text(dc, g, glyph, m_fonts.iconSmall, c.onAccent, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
			x += 2 * r + ui::Scale(10);
		}

		rc.SetRect(x, top, x + ui::Scale(120), top + rowH);
		ui::Text(dc, rc, row.name, m_fonts.label, icons ? c.text : c.muted,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE);

		rc.SetRect(rc.right, top, card.right - pad, top + rowH);
		/* 사용자 줄의 끝에는 로그인 버튼이 있다. 값은 그 앞에서 끝난다. */
		if (rows == m_info && i == INFO_USER && !m_rc_login.IsRectEmpty()) {
			rc.right = m_rc_login.left - ui::Scale(6);
		}
		ui::Text(dc, rc, row.value, m_fonts.label, row.level == LEVEL_BAD ? c.danger : c.text,
				DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
	}
}

/* 컨트롤이 아닌 모든 것. 좌표는 LayoutChildren 이 정해 둔 것을 그대로 쓴다. */
void CMainDlg::PaintBackground(HDC dc)
{
	const ui::Palette &c = ui::Colors();
	CRect client;
	HBRUSH brush;

	GetClientRect(&client);
	brush = CreateSolidBrush(c.bg);
	FillRect(dc, &client, brush);
	DeleteObject(brush);

	/* 상태 판: 큰 원 + 기호, 상태, 부제, 할 일 */
	if (!m_rc_hero.IsRectEmpty()) {
		const int cx = m_rc_hero.CenterPoint().x;
		const int cy = m_rc_hero.top + ui::Scale(52);
		const int r = ui::Scale(30);
		CRect rc;

		ui::RoundRect(dc, m_rc_hero, ui::Scale(10), c.card, c.border);

		/* 판 위쪽의 상태색 띠. 창을 흘깃 봐도 연결됐는지(청록) 아닌지 알 수 있다. */
		if (!c.highContrast) {
			CRect band(m_rc_hero.left + ui::Scale(10), m_rc_hero.top, m_rc_hero.right - ui::Scale(10),
					m_rc_hero.top + ui::Scale(3));
			HBRUSH bb = CreateSolidBrush(m_status_color);

			FillRect(dc, &band, bb);
			DeleteObject(bb);
		}

		/* 원 둘레의 옅은 띠. 고대비에서는 섞은 색이 시스템 색 조합을 깨므로 그리지 않는다. */
		if (!c.highContrast) {
			ui::Dot(dc, cx, cy, r + ui::Scale(8), Blend(m_status_color, c.card, 18));
		}
		ui::Dot(dc, cx, cy, r, m_status_color);
		rc.SetRect(cx - r, cy - r, cx + r, cy + r);
		ui::Text(dc, rc, m_status_icon, m_fonts.icon, c.onAccent, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

		rc.SetRect(m_rc_hero.left, m_rc_hero.top + ui::Scale(94), m_rc_hero.right, m_rc_hero.top + ui::Scale(122));
		ui::Text(dc, rc, m_status_title, m_fonts.hero, c.text, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

		rc.SetRect(m_rc_hero.left + ui::Scale(12), rc.bottom + ui::Scale(4), m_rc_hero.right - ui::Scale(12), rc.bottom + ui::Scale(24));
		ui::Text(dc, rc, m_status_sub, m_fonts.label, c.muted,
				DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

		if (!m_status_hint.IsEmpty()) {
			rc.SetRect(m_rc_hero.left + ui::Scale(24), rc.bottom + ui::Scale(4),
					m_rc_hero.right - ui::Scale(24), rc.bottom + ui::Scale(40));
			ui::Text(dc, rc, m_status_hint, m_fonts.label, m_status_hint_color,
					DT_CENTER | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS);
		}
	}

	if (!m_rc_security.IsRectEmpty()) {
		PaintCard(dc, m_rc_security, _T("보안 상태"), m_checks, CHECK_COUNT);
	}
	if (!m_rc_conn.IsRectEmpty()) {
		PaintCard(dc, m_rc_conn, _T("연결 정보"), m_info, INFO_COUNT);
	}
}

/* 버튼은 ui_controls 가 그린다. */
void CMainDlg::OnDrawItem(int id, LPDRAWITEMSTRUCT dis)
{
	if (ui::DrawButton(dis)) {
		return;
	}

	CDialogEx::OnDrawItem(id, dis);
}

/* 시스템 색이나 고대비 설정이 바뀌었다. 색을 다시 정하고 전부 다시 그린다. */
void CMainDlg::OnSysColorChange()
{
	CDialogEx::OnSysColorChange();

	ui::RefreshPalette();
	m_card_brush.DeleteObject();
	m_card_brush.CreateSolidBrush(ui::Colors().card);
	ui::MatchTitleBar(GetSafeHwnd());

	m_status_title.Empty();		/* UpdateStatus 가 색을 다시 고르게 */
	UpdateStatus();
	RedrawWindow(nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

/* ---- 레이아웃 ---------------------------------------------------------- */
void CMainDlg::OnSize(UINT type, int cx, int cy)
{
	CDialogEx::OnSize(type, cx, cy);

	if (type != SIZE_MINIMIZED) {
		LayoutChildren(cx, cy);
	}
}

/* 판의 크기는 96 DPI 기준 픽셀로 정하고 ui::Scale 로 늘린다. 다이얼로그 단위를 쓰지 않는
 * 것은, 이 창은 글자보다 판과 원의 크기가 먼저이기 때문이다. */
static int HomeHeight()
{
	const int cards = 2 * (HOME_CARD_TITLE_H + 8) + (CHECK_COUNT + INFO_COUNT) * HOME_ROW_H;

	return HOME_PAD + HOME_HERO_H + HOME_GAP + cards + HOME_GAP + HOME_LINKS_H + HOME_PAD;
}

void CMainDlg::FitWindow()
{
	CRect rc(0, 0, ui::Scale(HOME_WIDTH), ui::Scale(HomeHeight()));

	/* 클라이언트 크기 기준이라 테두리 / 캡션을 더해 준다. */
	AdjustWindowRectEx(&rc, GetStyle(), FALSE, GetExStyle());
	SetWindowPos(nullptr, 0, 0, rc.Width(), rc.Height(), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
	CenterWindow();

	GetClientRect(&rc);
	LayoutChildren(rc.Width(), rc.Height());
}

void CMainDlg::LayoutChildren(int cx, int)
{
	/* OnSize 는 컨트롤이 만들어지기 전에도 온다. */
	if (!GetDlgItem(IDC_CONNECT)) {
		return;
	}

	const int pad = ui::Scale(HOME_PAD);
	const int gap = ui::Scale(HOME_GAP);
	const int securityH = ui::Scale(HOME_CARD_TITLE_H + CHECK_COUNT * HOME_ROW_H + 8);
	const int connH = ui::Scale(HOME_CARD_TITLE_H + INFO_COUNT * HOME_ROW_H + 8);

	m_rc_hero.SetRect(pad, pad, cx - pad, pad + ui::Scale(HOME_HERO_H));
	m_rc_security.SetRect(pad, m_rc_hero.bottom + gap, cx - pad, m_rc_hero.bottom + gap + securityH);
	m_rc_conn.SetRect(pad, m_rc_security.bottom + gap, cx - pad, m_rc_security.bottom + gap + connH);

	/* 로그인 버튼은 연결 정보 판의 사용자 줄 끝에 붙는다. 로그인을 쓰지 않으면 없다. */
	if (m_issuer.IsEmpty()) {
		m_rc_login.SetRectEmpty();
	}
	else {
		const int rowTop = m_rc_conn.top + ui::Scale(HOME_CARD_TITLE_H) + INFO_USER * ui::Scale(HOME_ROW_H);
		const int w = ui::Scale(68);

		m_rc_login.SetRect(m_rc_conn.right - pad - w + ui::Scale(8), rowTop + ui::Scale(3),
				m_rc_conn.right - pad + ui::Scale(8), rowTop + ui::Scale(HOME_ROW_H) - ui::Scale(3));
	}
	GetDlgItem(IDC_LOGIN)->ShowWindow(m_rc_login.IsRectEmpty() ? SW_HIDE : SW_SHOW);

	const int btnInset = ui::Scale(28);
	const int btnH = ui::Scale(38);
	const int btnY = m_rc_hero.bottom - ui::Scale(18) - btnH;

	/* 글자가 바뀌는 곳은 버튼 위까지다. 버튼은 스스로 다시 그린다. */
	m_rc_hero_text.SetRect(m_rc_hero.left, m_rc_hero.top, m_rc_hero.right, btnY - 1);

	HDWP dwp = BeginDeferWindowPos(5);
	if (!dwp) {
		return;
	}

	auto Place = [&dwp, this](int id, int x, int y, int w, int h) {
		CWnd *c = GetDlgItem(id);
		if (c && w > 0 && h > 0) {
			dwp = DeferWindowPos(dwp, c->GetSafeHwnd(), nullptr, x, y, w, h,
					SWP_NOZORDER | SWP_NOACTIVATE);
		}
	};

	Place(IDC_CONNECT, m_rc_hero.left + btnInset, btnY, m_rc_hero.Width() - 2 * btnInset, btnH);
	if (!m_rc_login.IsRectEmpty()) {
		Place(IDC_LOGIN, m_rc_login.left, m_rc_login.top, m_rc_login.Width(), m_rc_login.Height());
	}

	/* 아래의 세 갈래길. 같은 폭으로 나눈다. */
	const int linksY = m_rc_conn.bottom + gap;
	const int linkW = (cx - 2 * pad) / 3;
	const int linkH = ui::Scale(HOME_LINKS_H);

	Place(IDC_SETTINGS, pad, linksY, linkW, linkH);
	Place(IDC_ENROLL, pad + linkW, linksY, linkW, linkH);
	Place(IDC_DIAG, pad + 2 * linkW, linksY, cx - pad - (pad + 2 * linkW), linkH);

	EndDeferWindowPos(dwp);

	/* 판의 자리가 바뀌었으니 바탕을 다시 그린다. */
	Invalidate(FALSE);
}

/* ---- 알림 영역 (트레이) ------------------------------------------------- */

void CMainDlg::TrayAdd()
{
	NOTIFYICONDATAW nid;

	ZeroMemory(&nid, sizeof(nid));
	nid.cbSize = sizeof(nid);
	nid.hWnd = GetSafeHwnd();
	nid.uID = TRAY_ID;
	nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
	nid.uCallbackMessage = WM_TRAYICON;
	nid.hIcon = static_cast<HICON>(LoadImageW(AfxGetInstanceHandle(), MAKEINTRESOURCEW(IDI_APP),
			IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED));
	wcsncpy_s(nid.szTip, ARRAYSIZE(nid.szTip), m_tray_tip, _TRUNCATE);

	m_tray_added = Shell_NotifyIconW(NIM_ADD, &nid) != FALSE;
	if (!m_tray_added) {
		/* 그러면 닫기가 예전처럼 프로그램을 끝낸다 (OnCancel). */
		AppendLog(_T("[gui] 알림 영역에 아이콘을 달지 못했습니다"));
	}
	else {
		/* 버전 4: 왼쪽 클릭이 NIN_SELECT 로, 오른쪽 클릭이 WM_CONTEXTMENU 로 오고, 키보드로
		 * 고른 것도 같은 길로 온다. 툴팁은 NIF_SHOWTIP 을 줘야 보인다. */
		nid.uVersion = NOTIFYICON_VERSION_4;
		Shell_NotifyIconW(NIM_SETVERSION, &nid);
	}
}

LRESULT CMainDlg::OnTaskbarCreated(WPARAM, LPARAM)
{
	TrayAdd();

	return 0;
}

/* 아이콘에 마우스를 올렸을 때의 글. 같은 글로 다시 부르지 않는다. */
void CMainDlg::TrayTip(const CString &tip)
{
	NOTIFYICONDATAW nid;

	if (tip == m_tray_tip) {
		return;
	}
	m_tray_tip = tip;
	if (!m_tray_added) {
		return;
	}

	ZeroMemory(&nid, sizeof(nid));
	nid.cbSize = sizeof(nid);
	nid.hWnd = GetSafeHwnd();
	nid.uID = TRAY_ID;
	nid.uFlags = NIF_TIP | NIF_SHOWTIP;
	wcsncpy_s(nid.szTip, ARRAYSIZE(nid.szTip), tip, _TRUNCATE);
	Shell_NotifyIconW(NIM_MODIFY, &nid);
}

/* Windows 의 알림(토스트)으로 띄운다. 사용자가 이 창을 보고 있으면 띄우지 않는다 — 같은
 * 것이 화면에 이미 있다. */
void CMainDlg::TrayNotify(LPCTSTR title, const CString &text, bool warning)
{
	NOTIFYICONDATAW nid;

	if (!m_tray_added) {
		return;
	}
	if (IsWindowVisible() && !IsIconic() && ::GetForegroundWindow() == GetSafeHwnd()) {
		return;
	}

	ZeroMemory(&nid, sizeof(nid));
	nid.cbSize = sizeof(nid);
	nid.hWnd = GetSafeHwnd();
	nid.uID = TRAY_ID;
	nid.uFlags = NIF_INFO;
	nid.dwInfoFlags = warning ? NIIF_WARNING : NIIF_INFO;
	wcsncpy_s(nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle), title, _TRUNCATE);
	wcsncpy_s(nid.szInfo, ARRAYSIZE(nid.szInfo), text, _TRUNCATE);
	Shell_NotifyIconW(NIM_MODIFY, &nid);
}

/* 상태가 바뀐 순간 중 사용자가 알아야 하는 것만 알린다. 연결 중 / 재연결 중 같은 지나가는
 * 상태는 알리지 않는다 — 몇 초 뒤면 결과가 나온다. 거부는 사유를 알게 되는 OnVpnPackets 가
 * 따로 알린다. */
void CMainDlg::NotifyTransition(tunnel_state_t prev, tunnel_state_t now, bool userStop)
{
	if (now == TUNNEL_STATE_CONNECTED && prev != TUNNEL_STATE_CONNECTED) {
		TrayNotify(_T("연결됨"), prev == TUNNEL_STATE_RECONNECTING ?
				CString(_T("사내망에 다시 연결됐습니다.")) : CString(_T("사내망에 연결됐습니다.")), false);
	}
	/* 서비스에서 떨어진 것(업데이트로 다시 뜬다)이나 서비스가 스스로 다시 올리는 중은 끊긴 것이 아니다. */
	else if (now == TUNNEL_STATE_STOPPED && !userStop && m_deny_reason == 0 &&
			(prev == TUNNEL_STATE_CONNECTED || prev == TUNNEL_STATE_RECONNECTING) &&
			m_link == VPN_REMOTE_UP && !vpn_remote_wanted(m_session)) {
		TrayNotify(_T("연결이 끊겼습니다"),
				CString(_T("다시 연결하려면 ztgate 를 열어 [연결] 을 누르세요.")), true);
	}
}

void CMainDlg::ShowFromTray()
{
	ShowWindow(SW_SHOW);
	if (IsIconic()) {
		ShowWindow(SW_RESTORE);
	}
	SetForegroundWindow();
}

LRESULT CMainDlg::OnTrayIcon(WPARAM wParam, LPARAM lParam)
{
	switch (LOWORD(lParam)) {
	case NIN_SELECT:
	case NIN_KEYSELECT:
	case NIN_BALLOONUSERCLICK:
		ShowFromTray();
		break;
	case WM_CONTEXTMENU:
		/* 버전 4 에서는 메뉴를 띄울 자리가 wParam 에 온다 (키보드로 연 경우도). */
		TrayMenu(GET_X_LPARAM(wParam), GET_Y_LPARAM(wParam));
		break;
	default:
		break;
	}

	return 0;
}

void CMainDlg::TrayMenu(int x, int y)
{
	enum { CMD_OPEN = 1, CMD_CONNECT, CMD_LOGIN, CMD_DIAG, CMD_EXIT };
	const bool loggedIn = !m_tokens.access.empty() || m_login.state != IPC_LOGIN_NONE;
	const bool active = vpn_session_active(m_session) != 0;
	HMENU menu = CreatePopupMenu();
	UINT cmd;

	if (!menu) {
		return;
	}

	AppendMenuW(menu, MF_STRING, CMD_OPEN, L"ztgate 열기");
	SetMenuDefaultItem(menu, CMD_OPEN, FALSE);
	AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
	const bool locked = active && m_policy.always_on;

	AppendMenuW(menu, MF_STRING | ((m_stopping || locked) ? MF_GRAYED : 0), CMD_CONNECT,
			locked ? L"회사 정책으로 늘 연결" : active ? L"연결 해제" : L"연결");
	if (!m_issuer.IsEmpty()) {
		CString item;

		if (m_login_thread && m_login_interactive) {
			item = _T("로그인 취소");
		}
		else if (loggedIn) {
			item = m_login_user.IsEmpty() ? CString(_T("로그아웃")) : _T("로그아웃 (") + m_login_user + _T(")");
		}
		else {
			item = _T("회사 계정으로 로그인");
		}
		AppendMenuW(menu, MF_STRING | ((m_login_thread && !m_login_interactive && !loggedIn) ? MF_GRAYED : 0),
				CMD_LOGIN, item);
	}
	AppendMenuW(menu, MF_STRING, CMD_DIAG, L"진단");
	AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(menu, MF_STRING, CMD_EXIT, L"종료");

	/* 이 창이 앞에 있지 않으면 메뉴 바깥을 눌러도 메뉴가 닫히지 않는다. 메뉴가 닫힌 뒤
	 * WM_NULL 을 보내는 것도 같은 문제를 피하는 관례다 (KB135788). */
	SetForegroundWindow();
	cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, x, y, 0,
			GetSafeHwnd(), nullptr);
	PostMessage(WM_NULL);
	DestroyMenu(menu);

	switch (cmd) {
	case CMD_OPEN:
		ShowFromTray();
		break;
	case CMD_CONNECT:
		/* 연결은 등록 / 설정을 물을 수 있으니 창을 먼저 보인다. 해제는 묻지 않는다. */
		if (!active) {
			ShowFromTray();
		}
		OnConnect();
		break;
	case CMD_LOGIN:
		OnLogin();
		break;
	case CMD_DIAG:
		OnDiag();
		break;
	case CMD_EXIT:
		m_exiting = true;
		CDialogEx::OnCancel();
		break;
	default:
		break;
	}
}

/* 닫기(X, Esc)는 알림 영역으로 숨기기다. 터널은 어차피 서비스가 맡고 있어 이 창을 닫아도
 * 끊기지 않는다. 숨겨 두면 차단되거나 끊겼을 때 알려 줄 수 있다. 끝내기는 알림 영역의
 * 메뉴에서 한다. 알림 영역에 아이콘을 달지 못했으면 예전처럼 닫는다. */
void CMainDlg::OnCancel()
{
	if (!m_tray_added || m_exiting) {
		CDialogEx::OnCancel();
		return;
	}

	ShowWindow(SW_HIDE);
	if (!m_told_tray) {
		m_told_tray = true;
		TrayNotify(_T("ztgate 는 알림 영역에서 계속 실행됩니다"),
				CString(_T("연결 상태가 바뀌면 알려 드립니다. 끝내려면 아이콘을 오른쪽 클릭해 [종료] 를 누르세요.")),
				false);
	}
}

/* Enter 가 다이얼로그를 닫지 않게. 기본 버튼은 SetUiState 가 정한다. */
void CMainDlg::OnOK()
{
}

/* ---- 종료 -------------------------------------------------------------- */
void CMainDlg::OnDestroy()
{
	RemovePropW(GetSafeHwnd(), kWindowProp);
	KillTimer(TIMER_TICK_ID);
	SaveSettings();

	if (m_tray_added) {
		NOTIFYICONDATAW nid;

		ZeroMemory(&nid, sizeof(nid));
		nid.cbSize = sizeof(nid);
		nid.hWnd = GetSafeHwnd();
		nid.uID = TRAY_ID;
		Shell_NotifyIconW(NIM_DELETE, &nid);
		m_tray_added = false;
	}

	/* 진단 창은 이 창이 가진 패킷과 로그를 가리킨다. 그것들보다 먼저 사라져야 한다. */
	if (m_diag.GetSafeHwnd()) {
		m_diag.DestroyWindow();
	}

	/* 이 창을 닫아도 터널은 닫히지 않는다. 터널은 서비스가 맡고 있고, destroy 는 그
	 * 서비스에서 떨어질 뿐이다. 다시 켜면 열려 있는 터널에 그대로 붙는다.
	 *
	 * 순서가 중요하다.
	 *  1) destroy 가 서비스에서 떨어지고 읽는 스레드가 끝날 때까지 기다린다. 이 시점
	 *     이후로는 새 PostMessage 가 생기지 않는다.
	 *  2) 그 뒤에 큐에 남아 있는 WM_VPN_LOG 의 버퍼를 해제한다. 창이 사라지면
	 *     이 메시지들은 처리되지 않으므로 여기서 치우지 않으면 그대로 샌다.
	 * ESC / Enter 로 닫을 때는 WM_CLOSE 없이 바로 WM_DESTROY 가 오므로
	 * 이 처리를 OnClose 가 아니라 여기에 둔다. */
	vpn_session_destroy(m_session);
	m_session = nullptr;
	vpn_session_drain(GetSafeHwnd());

	/* 로그인 워커를 그만두게 한다. 브라우저를 기다리는 중이면 0.25초 안에, 갱신 중이면
	 * IdP 의 응답(길면 10초)을 기다린다. 그 안에 끝나지 않으면 핸들을 남겨 둔다 — 워커가
	 * 아직 쓰고 있다. */
	WTSUnRegisterSessionNotification(GetSafeHwnd());

	/* 갱신 중이면 끝날 때까지 기다린다 (IdP 가 refresh token 을 바꿔 주는 중일 수 있고, 그 새
	 * 것을 저장하지 못하면 다음에 켤 때 브라우저로 다시 로그인해야 한다). 요청 둘이 각자 10초
	 * 안에 끝나므로 넉넉히 25초. 브라우저 로그인은 cancel 로 곧 끝난다. */
	if (m_login_thread) {
		SetEvent(m_login_cancel);
		if (WaitForSingleObject(m_login_thread, m_login_interactive ? 3000 : 25000) == WAIT_OBJECT_0) {
			CloseHandle(m_login_thread);
			CloseHandle(m_login_cancel);
		}
		m_login_thread = nullptr;
		m_login_cancel = nullptr;
	}
	else if (m_login_cancel) {
		CloseHandle(m_login_cancel);
		m_login_cancel = nullptr;
	}
	{
		MSG msg;

		/* 화면과 서비스는 이미 없다. 결과에서 저장할 것(바뀐 refresh token)만 챙긴다. */
		while (PeekMessageW(&msg, GetSafeHwnd(), WM_LOGIN_DONE, WM_LOGIN_DONE, PM_REMOVE)) {
			LoginDone *done = reinterpret_cast<LoginDone *>(msg.lParam);

			if (done->gen == m_login_gen && done->outcome.result == oidc::RESULT_OK &&
					!done->outcome.tokens.refresh.empty()) {
				oidc::SaveRefresh(LoginConfig(), done->outcome.tokens.refresh);
			}
			oidc::Wipe(&done->outcome.tokens);
			delete done;
		}
	}
	/* 메모리의 토큰을 지운다. 저장해 둔 refresh token 은 남긴다 — 다음에 켤 때 이어서 로그인한다. */
	oidc::Wipe(&m_tokens);

	CDialogEx::OnDestroy();

	/* 컨트롤이 쓰던 글꼴은 컨트롤이 사라진 뒤에 지운다. */
	ui::DestroyFonts(&m_fonts);
}
