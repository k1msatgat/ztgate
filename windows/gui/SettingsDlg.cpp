#include "framework.h"
#include "resource.h"
#include "SettingsDlg.h"
#include "tunnel.h"
#include "Oidc.h"

CSettingsDlg::CSettingsDlg(CWnd *parent)
	: CDialogEx(IDD_SETTINGS, parent)
	, m_point_id(0)
{
}

BEGIN_MESSAGE_MAP(CSettingsDlg, CDialogEx)
END_MESSAGE_MAP()

void CSettingsDlg::PointAt(int id, const CString &message)
{
	m_point_id = id;
	m_point_msg = message;
}

bool CSettingsDlg::Check(const CString &server, const CString &port, const CString &adapter,
		int *bad_id, CString *why)
{
	const int port_num = _ttoi(port);

	if (tunnel_check_servers(server) < 0) {
		*bad_id = IDC_SERVER;
		*why = _T("서버의 이름이나 IP 주소를 적어 주세요. 예) vpn.example.com, 203.0.113.10\n")
			_T("서버가 여럿이면 쉼표로 넷까지: vpn1.example.com, vpn2.example.com");
		return false;
	}
	if (port_num <= 0 || port_num > 65535) {
		*bad_id = IDC_PORT;
		*why = _T("1 부터 65535 사이의 숫자여야 합니다.");
		return false;
	}
	if (adapter.IsEmpty() || adapter.GetLength() >= TUNNEL_ADAPTER_NAME_LEN) {
		*bad_id = IDC_ADAPTER;
		*why = _T("터널 어댑터의 이름입니다. 비워 둘 수 없습니다.");
		return false;
	}

	return true;
}

bool CSettingsDlg::CheckLogin(const CString &issuer, const CString &client_id, int *bad_id, CString *why)
{
	if (issuer.IsEmpty()) {
		return true;	/* 사용자 로그인을 쓰지 않는다 */
	}
	if (!oidc::IssuerUsable(issuer, why)) {
		*bad_id = IDC_ISSUER;
		return false;
	}
	if (client_id.IsEmpty()) {
		*bad_id = IDC_CLIENT_ID;
		*why = _T("IdP 에 등록된 이 앱의 클라이언트 ID 입니다. 관리자가 알려 줍니다.");
		return false;
	}

	return true;
}

BOOL CSettingsDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetDlgItemText(IDC_SERVER, m_server);
	SetDlgItemText(IDC_PORT, m_port);
	SetDlgItemText(IDC_ADAPTER, m_adapter);
	SetDlgItemText(IDC_ISSUER, m_issuer);
	SetDlgItemText(IDC_CLIENT_ID, m_client_id);
	SetDlgItemText(IDC_SCOPE, m_scope);

	/* 빈 칸에 무엇을 적는지 흐린 글씨로 알려 준다. */
	GetDlgItem(IDC_SERVER)->SendMessage(EM_SETCUEBANNER, FALSE, (LPARAM)L"203.0.113.10");
	GetDlgItem(IDC_PORT)->SendMessage(EM_SETCUEBANNER, FALSE, (LPARAM)L"9000");
	GetDlgItem(IDC_ADAPTER)->SendMessage(EM_SETCUEBANNER, FALSE, (LPARAM)L"ztgate");
	GetDlgItem(IDC_ISSUER)->SendMessage(EM_SETCUEBANNER, FALSE, (LPARAM)L"https://idp.example.com/realms/corp");
	GetDlgItem(IDC_CLIENT_ID)->SendMessage(EM_SETCUEBANNER, FALSE, (LPARAM)L"ztgate");
	GetDlgItem(IDC_SCOPE)->SendMessage(EM_SETCUEBANNER, FALSE, (LPARAM)L"openid  (IdP 에 따라 offline_access 등을 더함)");

	if (m_point_id != 0) {
		FieldError(m_point_id, m_point_msg);
		return FALSE;	/* 포커스를 직접 옮겼다 */
	}

	return TRUE;
}

void CSettingsDlg::OnOK()
{
	CString server, port, adapter, issuer, client_id, scope, why;
	int bad = 0;

	GetDlgItemText(IDC_SERVER, server);
	GetDlgItemText(IDC_PORT, port);
	GetDlgItemText(IDC_ADAPTER, adapter);
	GetDlgItemText(IDC_ISSUER, issuer);
	GetDlgItemText(IDC_CLIENT_ID, client_id);
	GetDlgItemText(IDC_SCOPE, scope);
	server.Trim();
	port.Trim();
	adapter.Trim();
	issuer.Trim();
	client_id.Trim();
	scope.Trim();

	if (!Check(server, port, adapter, &bad, &why) || !CheckLogin(issuer, client_id, &bad, &why)) {
		FieldError(bad, why);
		return;
	}

	m_server = server;
	m_port = port;
	m_adapter = adapter;
	m_issuer = issuer;
	m_client_id = client_id;
	m_scope = scope;

	CDialogEx::OnOK();
}

/* 잘못 적은 칸을 가리키며 말한다. 메시지 상자는 확인을 누르고 나면 어느 칸이었는지
 * 다시 찾아야 한다. */
void CSettingsDlg::FieldError(int id, LPCTSTR message)
{
	CWnd *edit = GetDlgItem(id);
	EDITBALLOONTIP tip;

	ZeroMemory(&tip, sizeof(tip));
	tip.cbStruct = sizeof(tip);
	tip.pszTitle = L"입력을 확인해 주세요";
	tip.pszText = message;
	tip.ttiIcon = TTI_WARNING;

	GotoDlgCtrl(edit);
	edit->SendMessage(EM_SETSEL, 0, -1);
	edit->SendMessage(EM_SHOWBALLOONTIP, 0, reinterpret_cast<LPARAM>(&tip));
}
