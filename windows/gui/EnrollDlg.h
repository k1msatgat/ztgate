#pragma once

#ifndef __AFXWIN_H__
#error "include framework.h before EnrollDlg.h"
#endif

#include "device.h"
#include "ui_theme.h"
#include "ui_controls.h"

/* 방금 만든 기기 ID 와 키를 한 번 보여 주는 창.
 *
 * 키는 등록 직후 이 창에서만 볼 수 있다. 이후에는 DPAPI 로 감싼 값만 남고 프로그램도
 * 다시 보여 주지 않는다. 관리자가 이 값을 서버의 기기 목록에 옮겨 적는다. */
class CEnrollDlg : public CDialogEx
{
public:
	CEnrollDlg(const device_t &dev, CWnd *parent);
	~CEnrollDlg() override;

protected:
	BOOL OnInitDialog() override;
	afx_msg void OnCopy();
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC *pDC);
	afx_msg HBRUSH OnCtlColor(CDC *pDC, CWnd *pWnd, UINT type);
	afx_msg void OnDrawItem(int id, LPDRAWITEMSTRUCT dis);
	afx_msg void OnDestroy();

	DECLARE_MESSAGE_MAP()

private:
	static CString Hex(const uint8_t *buf, int len);

	CString m_id;
	CString m_key;
	ui::Fonts m_fonts;
	CBrush m_card_brush;
};

/* 등록 코드를 받는 창.
 *
 * 기기를 서버에 올리는 보통의 길이다. 관리자가 만든 코드를 적으면 이 기기가 ID 와 키를
 * 만들어 암호화된 세션으로 서버에 올린다. 키가 화면이나 클립보드를 거치지 않는다.
 * 코드 없이 ID 와 키를 보고 손으로 옮기는 예전 방식은 [코드 없이...] 로 남겨 뒀다 —
 * 서버가 등록 코드를 받지 않게 떠 있을 때 쓴다. */
class CEnrollCodeDlg : public CDialogEx
{
public:
	/* DoModal 의 결과. IDOK 면 m_code 에 적은 코드(또는 초대 링크)가 있다. 열기 전에 넣어 두면 칸에 채운다. */
	enum { RESULT_MANUAL = 100 };

	/* where 는 어느 서버에 올리는지를 창에 보여 줄 글이다. */
	CEnrollCodeDlg(const CString &where, CWnd *parent);

	CString m_code;

protected:
	BOOL OnInitDialog() override;
	void OnOK() override;
	afx_msg void OnManual();

	DECLARE_MESSAGE_MAP()

private:
	CString m_where;
};
