#pragma once

#ifndef __AFXWIN_H__
#error "include framework.h before SettingsDlg.h"
#endif

/* 연결 설정: 서버 주소, 포트, 터널 어댑터의 이름, 사용자 로그인에 쓸 IdP.
 *
 * 전에는 주 창 머리에 입력 칸 넷이 늘 펼쳐져 있었다. 한 번 정하면 거의 바꾸지 않는 값인데
 * 화면의 가장 좋은 자리를 차지했고, 터널 IP 칸은 서버가 정해 주는 값이라 적을 수도 없었다.
 * 상용 에이전트처럼 설정은 따로 열고, 주 창은 지금 쓰는 값을 보여 주기만 한다. */
class CSettingsDlg : public CDialogEx
{
public:
	explicit CSettingsDlg(CWnd *parent);

	/* 문제가 있는 칸을 처음부터 가리키며 연다. 0 이면 없음. */
	void PointAt(int id, const CString &message);

	CString m_server;
	CString m_port;
	CString m_adapter;
	CString m_issuer;	/* 비어 있으면 사용자 로그인을 쓰지 않는다 */
	CString m_client_id;
	CString m_scope;	/* 비어 있으면 openid */

	/* 관리 정책이 정한 칸. 보이기만 하고 고칠 수 없다. */
	bool m_lock_servers;	/* 서버와 포트 */
	bool m_lock_issuer;
	bool m_lock_client_id;

	/* 값이 맞는지. 아니면 틀린 칸의 ID 와 이유를 돌려준다. 주 창이 연결 전에도 쓴다. */
	static bool Check(const CString &server, const CString &port, const CString &adapter,
			int *bad_id, CString *why);
	static bool CheckLogin(const CString &issuer, const CString &client_id, int *bad_id, CString *why);

protected:
	BOOL OnInitDialog() override;
	void OnOK() override;

	DECLARE_MESSAGE_MAP()

private:
	void FieldError(int id, LPCTSTR message);

	int m_point_id;
	CString m_point_msg;
};
