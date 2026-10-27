#include "framework.h"
#include "resource.h"
#include "EnrollDlg.h"

BEGIN_MESSAGE_MAP(CEnrollDlg, CDialogEx)
	ON_BN_CLICKED(IDC_ENROLL_COPY, &CEnrollDlg::OnCopy)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_CTLCOLOR()
	ON_WM_DRAWITEM()
	ON_WM_DESTROY()
END_MESSAGE_MAP()

CEnrollDlg::CEnrollDlg(const device_t &dev, CWnd *parent)
	: CDialogEx(IDD_ENROLL, parent)
	, m_id(Hex(dev.id, DEVICE_ID_LEN))
	, m_key(Hex(dev.key, AUTH_KEY_LEN))
{
	ZeroMemory(&m_fonts, sizeof(m_fonts));
}

/* CString 은 해제할 때 내용을 지우지 않는다. 키의 16진 문자열이 해제된 힙에 남지
 * 않게 직접 지운다. */
CEnrollDlg::~CEnrollDlg()
{
	int len = m_key.GetLength();

	SecureZeroMemory(m_key.GetBuffer(len), len * sizeof(TCHAR));
	m_key.ReleaseBuffer(0);
}

CString CEnrollDlg::Hex(const uint8_t *buf, int len)
{
	CString s;
	CString t;

	for (int i = 0; i < len; i++) {
		t.Format(_T("%02x"), buf[i]);
		s += t;
	}

	return s;
}

BOOL CEnrollDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	ui::MatchTitleBar(GetSafeHwnd());
	ui::CreateFonts(reinterpret_cast<HFONT>(SendMessage(WM_GETFONT)), &m_fonts);
	m_card_brush.CreateSolidBrush(ui::Colors().card);

	/* 이 창에서 할 일은 복사다. 닫기는 그다음이다. */
	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_ENROLL_COPY), ui::BUTTON_PRIMARY);
	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDOK), ui::BUTTON_SECONDARY);

	/* 0 과 O, 1 과 l 이 구분되도록 고정폭으로 보여 준다. */
	GetDlgItem(IDC_ENROLL_ID)->SetFont(CFont::FromHandle(m_fonts.mono));
	GetDlgItem(IDC_ENROLL_KEY)->SetFont(CFont::FromHandle(m_fonts.mono));

	SetDlgItemText(IDC_ENROLL_ID, m_id);
	SetDlgItemText(IDC_ENROLL_KEY, m_key);

	return TRUE;
}

/* "<id> <key>" 한 줄을 클립보드에 넣는다.
 *
 * 클립보드에 넘긴 메모리는 SetClipboardData 가 성공하는 순간 시스템 소유가 된다.
 * 그 뒤로는 우리가 해제하면 안 되고, 실패했을 때만 직접 해제한다. */
void CEnrollDlg::OnCopy()
{
	CString line = m_id + _T(" ") + m_key;
	size_t bytes = ((size_t)line.GetLength() + 1) * sizeof(wchar_t);
	HGLOBAL mem;

	if (!OpenClipboard()) {
		AfxMessageBox(_T("클립보드를 열 수 없습니다."), MB_ICONWARNING);
		return;
	}

	EmptyClipboard();
	mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
	if (mem) {
		memcpy(GlobalLock(mem), (LPCWSTR)line, bytes);
		GlobalUnlock(mem);
		if (!SetClipboardData(CF_UNICODETEXT, mem)) {
			GlobalFree(mem);
		}
	}
	CloseClipboard();

	SecureZeroMemory(line.GetBuffer(), bytes);
	line.ReleaseBuffer(0);

	SetDlgItemText(IDC_ENROLL_COPY, _T("복사됨 ✓"));
	GetDlgItem(IDC_ENROLL_COPY)->Invalidate(FALSE);
}

/* ---- 그리기 ------------------------------------------------------------ */

/* 창 전체가 흰 판 하나다. 제목, 안내, 경고를 직접 그린다. 경고는 본문과 같은 크기의
 * 회색 글씨로 두면 읽히지 않는다 — 이 창에서 놓치면 안 되는 한 줄이다. */
void CEnrollDlg::OnPaint()
{
	CPaintDC paint(this);
	const ui::Palette &c = ui::Colors();
	const int pad = ui::Scale(24);
	HDC dc = paint.GetSafeHdc();
	CRect client;
	CRect rc;
	HBRUSH brush;

	GetClientRect(&client);
	brush = CreateSolidBrush(c.card);
	FillRect(dc, &client, brush);
	DeleteObject(brush);

	rc.SetRect(pad, ui::Scale(18), client.right - pad, ui::Scale(48));
	ui::Text(dc, rc, L"이 기기의 ID 와 키를 만들었습니다", m_fonts.title, c.text,
			DT_LEFT | DT_TOP | DT_SINGLELINE);

	rc.SetRect(pad, ui::Scale(50), client.right - pad, ui::Scale(72));
	ui::Text(dc, rc, L"아래 두 값을 서버의 기기 목록에 등록하면 이 기기로 접속할 수 있습니다.",
			m_fonts.label, c.muted, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS);

	/* 경고 띠: 입력 칸 아래, 버튼 위 */
	CRect key;
	GetDlgItem(IDC_ENROLL_KEY)->GetWindowRect(&key);
	ScreenToClient(&key);

	rc.SetRect(pad, key.bottom + ui::Scale(14), client.right - pad, key.bottom + ui::Scale(44));
	ui::RoundRect(dc, rc, ui::Scale(6), c.dangerBg, CLR_NONE);
	rc.DeflateRect(ui::Scale(12), 0);
	ui::Text(dc, rc, L"키는 이 창을 닫으면 다시 볼 수 없습니다. 지금 복사해 두세요.",
			m_fonts.strong, c.danger, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

BOOL CEnrollDlg::OnEraseBkgnd(CDC *)
{
	return TRUE;
}

HBRUSH CEnrollDlg::OnCtlColor(CDC *pDC, CWnd *pWnd, UINT type)
{
	if (type == CTLCOLOR_STATIC) {
		/* 라벨은 흐리게, 읽기 전용 편집창(값)은 또렷하게. 둘 다 CTLCOLOR_STATIC 으로 온다. */
		const int id = pWnd->GetDlgCtrlID();
		const bool value = (id == IDC_ENROLL_ID || id == IDC_ENROLL_KEY);

		pDC->SetBkColor(ui::Colors().card);
		pDC->SetTextColor(value ? ui::Colors().text : ui::Colors().muted);

		return static_cast<HBRUSH>(m_card_brush.GetSafeHandle());
	}

	return CDialogEx::OnCtlColor(pDC, pWnd, type);
}

void CEnrollDlg::OnDrawItem(int id, LPDRAWITEMSTRUCT dis)
{
	if (ui::DrawButton(dis)) {
		return;
	}

	CDialogEx::OnDrawItem(id, dis);
}

void CEnrollDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	ui::DestroyFonts(&m_fonts);
}

/* ---- 등록 코드 ----------------------------------------------------------- */
BEGIN_MESSAGE_MAP(CEnrollCodeDlg, CDialogEx)
	ON_BN_CLICKED(IDC_ENROLL_MANUAL, &CEnrollCodeDlg::OnManual)
END_MESSAGE_MAP()

CEnrollCodeDlg::CEnrollCodeDlg(const CString &where, CWnd *parent)
	: CDialogEx(IDD_ENROLL_CODE, parent)
	, m_where(where)
{
}

BOOL CEnrollCodeDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetDlgItemText(IDC_ENROLL_ID, m_where);
	GetDlgItem(IDC_ENROLL_CODE)->SendMessage(EM_SETCUEBANNER, TRUE, (LPARAM)L"XXXXX-XXXXX-XXXXX-XXXXX-XXXXX 또는 초대 링크");
	SetDlgItemText(IDC_ENROLL_CODE, m_code);
	GetDlgItem(IDC_ENROLL_CODE)->SetFocus();

	/* 포커스를 직접 옮겼으므로 FALSE 를 돌려준다. TRUE 면 첫 컨트롤로 되돌아간다. */
	return FALSE;
}

void CEnrollCodeDlg::OnOK()
{
	GetDlgItemText(IDC_ENROLL_CODE, m_code);
	m_code.Trim();

	/* 빈 채로 누른 것은 닫으라는 뜻이 아니다. 형식이 맞는지는 코어가 본다. */
	if (m_code.IsEmpty()) {
		MessageBeep(MB_ICONWARNING);
		GetDlgItem(IDC_ENROLL_CODE)->SetFocus();
		return;
	}

	CDialogEx::OnOK();
}

void CEnrollCodeDlg::OnManual()
{
	EndDialog(RESULT_MANUAL);
}
