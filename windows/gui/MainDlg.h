#pragma once

/* framework.h 를 먼저 포함해야 한다 (Winsock2 -> MFC 순서). */
#ifndef __AFXWIN_H__
#error "include framework.h before MainDlg.h"
#endif

#include "vpn_remote.h"
#include "posture.h"
#include "policy.h"
#include <deque>

#include "PacketStore.h"
#include "DiagDlg.h"
#include "Oidc.h"
#include "ui_theme.h"
#include "ui_controls.h"

/* 한 번에 링버퍼에서 꺼내는 패킷 수. 너무 크면 UI 가 한 번에 오래 멈춘다. */
#define PACKET_DRAIN_BATCH 256

/* 알림 영역 아이콘이 보내는 메시지와 아이콘 번호 (이 창에 하나뿐이다) */
#define WM_TRAYICON	(WM_APP + 20)
#define TRAY_ID		1

/* 로그인 워커가 끝났다. lParam = LoginDone* (받는 쪽이 지운다) */
#define WM_LOGIN_DONE	(WM_APP + 21)

/* 토큰을 갱신하지 못했을 때 다시 해 보는 간격 */
#define LOGIN_RETRY_MS	30000

#define TIMER_TICK_ID 1
#define TIMER_TICK_MS 500

/* 이 PC 의 보안 상태를 다시 읽는 주기 (틱 수). 코어의 보고 주기와 같은 2초. */
#define POSTURE_REFRESH_TICKS 4

/* 주 창의 치수 (96 DPI 기준 픽셀, ui::Scale 로 늘린다) */
#define HOME_WIDTH		380
#define HOME_PAD		16	/* 창 가장자리와 판 안쪽의 여백 */
#define HOME_GAP		12	/* 판 사이 */
#define HOME_HERO_H		250	/* 상태 판 */
#define HOME_CARD_TITLE_H	40	/* 판 제목 줄 */
#define HOME_ROW_H		30	/* 판의 한 줄 */
#define HOME_LINKS_H		30	/* 아래의 설정 / 기기 등록 / 진단 */

/* 보안 상태 판의 줄 */
enum {
	CHECK_FIREWALL = 0,
	CHECK_ANTIVIRUS,
	CHECK_DISK,
	CHECK_OS,
	CHECK_SERVER,
	CHECK_COUNT
};

/* 연결 정보 판의 줄 */
enum {
	INFO_USER = 0,
	INFO_SERVER,
	INFO_TUNNEL,
	INFO_TRAFFIC,
	INFO_DEVICE,
	INFO_COUNT
};

/* 한 줄의 판정. 색과 기호를 고르는 데만 쓴다 — 뜻은 글자에도 있다 (고대비, 색맹). */
enum CheckLevel {
	LEVEL_NONE = 0,		/* 아직 모름 / 해당 없음 */
	LEVEL_OK,
	LEVEL_BAD
};

struct HomeRow {
	CString name;
	CString value;
	int level;		/* CheckLevel */
};

/* 주 창: 상용 VPN 에이전트처럼 작은 고정 크기 창.
 *
 *   +----------------------------+
 *   |          ( ✓ )             |  상태 판: 큰 기호, 상태, 부제, 할 일, [연결]
 *   |         연결됨              |
 *   |  사내망에 연결됨 · 00:12:31 |
 *   |   [       연결 해제      ]  |
 *   +----------------------------+
 *   | 보안 상태                   |  이 PC 의 방화벽 / 백신 / 빌드, 서버의 판정
 *   +----------------------------+
 *   | 연결 정보                   |  서버, 터널 주소, 주고받은 양, 기기
 *   +----------------------------+
 *     설정     기기 등록     진단      자주 쓰지 않는 곳으로 가는 길
 *
 * 패킷과 로그는 진단 창(CDiagDlg)에 있다. 이 창은 "연결됐는가, 안 됐으면 왜, 무엇을 하면
 * 되는가"에 답한다. */
class CMainDlg : public CDialogEx
{
public:
	explicit CMainDlg(CWnd *parent = nullptr);

protected:
	BOOL OnInitDialog() override;
	void OnOK() override;
	void OnCancel() override;

	afx_msg void OnConnect();
	afx_msg void OnEnroll();
	afx_msg void OnDiag();
	afx_msg void OnSettings();
	afx_msg void OnLogin();
	afx_msg void OnDestroy();
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg void OnTimer(UINT_PTR id);
	afx_msg HBRUSH OnCtlColor(CDC *pDC, CWnd *pWnd, UINT type);

	/* 바탕, 판, 상태는 컨트롤이 아니라 다이얼로그가 직접 그린다. */
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC *pDC);
	afx_msg LRESULT OnPrintClient(WPARAM wParam, LPARAM lParam);
	afx_msg void OnDrawItem(int id, LPDRAWITEMSTRUCT dis);
	afx_msg void OnSysColorChange();

	/* 워커 스레드가 PostMessage 로 보낸 것들. 모두 UI 스레드에서 처리된다. */
	afx_msg LRESULT OnVpnLog(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnVpnState(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnVpnDone(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnVpnPackets(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnVpnService(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnVpnDevice(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnVpnError(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnVpnLogin(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnLoginDone(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnSessionChange(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnTrayIcon(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnTaskbarCreated(WPARAM wParam, LPARAM lParam);
	bool ServiceReady();

	DECLARE_MESSAGE_MAP()

private:
	bool BuildConfig(tunnel_config_t &cfg);
	void AppendLog(const CString &text);
	void RequestDisconnect();
	bool EditSettings(int bad_id, const CString &why);
	bool SettingsUsable();
	void SetUiState(tunnel_state_t state);
	void UpdateStatus();
	CString DenyHint() const;
	void UpdateInfo();
	void PaintBackground(HDC dc);
	void PaintCard(HDC dc, const CRect &card, LPCTSTR title, const HomeRow *rows, int count);
	void LayoutChildren(int cx, int cy);
	void FitWindow();
	void LoadSettings();
	void SaveSettings();

	/* 알림 영역: 창을 닫아도 남아 상태를 알린다 */
	void TrayAdd();
	void TrayTip(const CString &tip);
	void TrayNotify(LPCTSTR title, const CString &text, bool warning);
	void TrayMenu(int x, int y);
	void ShowFromTray();
	void NotifyTransition(tunnel_state_t prev, tunnel_state_t now, bool userStop);

	/* 사용자 로그인: IdP 에서 토큰을 받아(브라우저 또는 refresh token) 서비스에 건넨다 */
	void StartLogin(bool interactive);
	void Logout(const CString &why);
	void SendToken();
	void ScheduleRefresh(__int64 expires_at);
	void UpdateLoginButton();
	void CheckLoginExpiry();
	oidc::Config LoginConfig() const;
	HomeRow LoginRow() const;

	void LoadDeviceId();
	void TrackAuth(const tunnel_packet_t &p);
	void RefreshPosture(bool collect);
	static CString LocalStateName(int state);

	vpn_session_t *m_session;
	CPacketStore m_store;
	tunnel_state_t m_state;
	ULONGLONG m_connected_at;	/* GetTickCount64, 0 이면 미연결 */

	/* 이 PC 의 지금 상태. UI 가 직접 읽는다 (연결하지 않아도 보인다). 서버에 실제로
	 * 보고한 값은 진단 창의 KEEPALIVE 행에 있다. */
	posture_t m_local;
	int m_deny_reason;		/* 마지막 거부 사유, 없으면 0 */
	CString m_device_id;		/* 비어 있으면 미등록 */
	int m_posture_ticks;

	uint32_t m_session_idx;		/* 지금 세션, 없으면 0 */
	CString m_tun_text;		/* 서버가 배정한 터널 주소. 같은 값으로 다시 그리지 않으려고 기억한다 */

	/* 연결 설정 (레지스트리에 둔다). 설정 창에서만 바뀐다. */
	CString m_server;
	ztgate_policy_t m_policy;	/* 관리 정책 (policy.h). 정한 것은 설정보다 앞선다 */
	CString m_port;
	CString m_adapter;
	int m_link;			/* 서비스와의 연결 (vpn_remote_link_t) */
	bool m_stopping;		/* 해제를 요청하고 워커가 끝나기를 기다리는 중 */

	/* 패킷과 로그는 진단 창이 닫혀 있어도 여기에 쌓는다. 진단 창은 이것을 보여 줄 뿐이다. */
	std::deque<CString> m_logLines;
	CDiagDlg m_diag;

	/* 사용자 로그인. 설정(IdP)은 설정 창에서 바뀐다. */
	CString m_issuer;		/* 비어 있으면 사용자 로그인을 쓰지 않는다 */
	CString m_client_id;
	CString m_scope;
	oidc::Tokens m_tokens;		/* access 가 비어 있으면 로그인하지 않은 것 */
	ipc_login_t m_login;		/* 서비스가 알려 준 서버의 답 */
	HANDLE m_login_thread;		/* 로그인 / 갱신 워커. 없으면 nullptr */
	HANDLE m_login_cancel;		/* manual-reset. 브라우저 로그인을 그만둔다 */
	bool m_login_interactive;	/* 워커가 브라우저 로그인 중이다 (아니면 갱신) */
	unsigned m_login_gen;		/* 로그아웃하면 는다. 그 전에 시작한 워커의 결과는 버린다 */
	ULONGLONG m_refresh_at;		/* 다음 갱신 (GetTickCount64), 0 이면 없음 */
	CString m_login_error;		/* 마지막 실패. 연결 정보 판에 보인다 */
	CString m_login_user;		/* 서버가 마지막으로 확인해 준 사용자 */
	bool m_expired_retry;		/* 서버가 만료라고 해서 한 번 갱신했다. 또 그러면 멈춘다 */
	int m_expiry_stage;		/* 만료를 알린 단계: 0 없음, 1 곧 끝남, 2 끝남 */
	uint32_t m_notified_login;	/* 이미 알린 서버의 거절 (login_status_t + 1), 0 이면 없음 */
	bool m_suspended;		/* 이 Windows 세션이 화면에서 떨어졌다. 그동안 서비스에 토큰을 두지 않는다 */

	bool m_tray_added;		/* 알림 영역에 아이콘을 달았다 */
	bool m_told_tray;		/* "알림 영역에서 계속 실행됩니다"를 한 번 알렸다 */
	bool m_exiting;			/* 알림 영역 메뉴의 [종료] — 닫기를 숨기기로 바꾸지 않는다 */
	int m_notified_deny;		/* 이미 알린 거부 사유. 같은 거부를 되풀이해 알리지 않는다 */
	CString m_tray_tip;

	/* 직접 그리는 것들. 자리는 LayoutChildren 이 정하고 PaintBackground 가 그린다. */
	ui::Fonts m_fonts;
	CBrush m_card_brush;		/* 판 위에 놓인 컨트롤의 바탕 */
	CRect m_rc_hero;		/* 상태 판 */
	CRect m_rc_hero_text;		/* 상태 판에서 글자가 바뀌는 곳 (버튼 위) */
	CRect m_rc_security;		/* 보안 상태 판 */
	CRect m_rc_conn;		/* 연결 정보 판 */
	CRect m_rc_login;		/* 사용자 줄 끝의 로그인 버튼. 로그인을 쓰지 않으면 빈 사각형 */

	CString m_status_title;
	CString m_status_sub;
	CString m_status_hint;		/* 무엇을 하면 되는지. 없으면 비어 있다 */
	LPCWSTR m_status_icon;
	COLORREF m_status_color;
	COLORREF m_status_hint_color;

	HomeRow m_checks[CHECK_COUNT];
	HomeRow m_info[INFO_COUNT];
};
