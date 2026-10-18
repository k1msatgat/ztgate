#include "framework.h"
#include <uxtheme.h>
#include "resource.h"
#include "DiagDlg.h"
#include "PacketText.h"

#ifdef _MSC_VER
#pragma comment(lib, "uxtheme.lib")
#endif

/* 리스트 열 정의. 폭은 다이얼로그 단위로 적고 MapDialogRect 로 픽셀로 바꾼다 —
 * 고정 픽셀로 적으면 고DPI 에서 글자가 잘린다. */
static const struct {
	LPCTSTR title;
	int du_width;
	int format;
} COLUMNS[] = {
	{ _T("#"),        28, LVCFMT_RIGHT },
	{ _T("경과"),     44, LVCFMT_RIGHT },
	{ _T("방향"),     34, LVCFMT_CENTER },
	{ _T("타입"),     52, LVCFMT_LEFT },
	{ _T("세션"),     46, LVCFMT_LEFT },
	{ _T("counter"),  40, LVCFMT_RIGHT },
	{ _T("요약"),    150, LVCFMT_LEFT },
	{ _T("길이"),     30, LVCFMT_RIGHT },
	{ _T("결과"),     64, LVCFMT_LEFT },
};

#define COLUMN_COUNT ((int)(sizeof(COLUMNS) / sizeof(COLUMNS[0])))
static_assert(COLUMN_COUNT == pkt::COL_COUNT, "COLUMNS must follow pkt::Column");

CDiagDlg::CDiagDlg(CPacketStore &store, std::deque<CString> &log)
	: CDialogEx(IDD_DIAG, nullptr)
	, m_store(store)
	, m_logLines(log)
	, m_tabs(nullptr)
	, m_sep_y(0)
{
	ZeroMemory(&m_fonts, sizeof(m_fonts));
}

void CDiagDlg::DoDataExchange(CDataExchange *pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PACKETS, m_packets);
	DDX_Control(pDX, IDC_LOG, m_log);
	DDX_Control(pDX, IDC_DETAIL, m_detail);
}

BEGIN_MESSAGE_MAP(CDiagDlg, CDialogEx)
	ON_BN_CLICKED(IDC_CLEAR, &CDiagDlg::OnClear)
	ON_BN_CLICKED(IDC_SAVE, &CDiagDlg::OnSave)
	ON_BN_CLICKED(IDC_HIDE_KA, &CDiagDlg::OnFilterChanged)
	ON_BN_CLICKED(IDC_ONLY_DROPS, &CDiagDlg::OnFilterChanged)
	ON_CBN_SELCHANGE(IDC_FILTER_DIR, &CDiagDlg::OnFilterChanged)
	ON_CONTROL(UI_TABS_CHANGED, IDC_TAB, &CDiagDlg::OnTabChanged)
	ON_WM_DESTROY()
	ON_WM_SIZE()
	ON_WM_GETMINMAXINFO()
	ON_WM_TIMER()
	ON_WM_CTLCOLOR()
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_DRAWITEM()
	ON_WM_SYSCOLORCHANGE()
	ON_MESSAGE(WM_PRINTCLIENT, &CDiagDlg::OnPrintClient)
	ON_NOTIFY(LVN_GETEMPTYMARKUP, IDC_PACKETS, &CDiagDlg::OnGetEmptyMarkup)
	ON_NOTIFY(LVN_GETDISPINFO, IDC_PACKETS, &CDiagDlg::OnGetDispInfo)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_PACKETS, &CDiagDlg::OnPacketCustomDraw)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_PACKETS, &CDiagDlg::OnPacketSelChanged)
END_MESSAGE_MAP()

/* ---- 열기 / 닫기 ------------------------------------------------------- */

/* 모덜리스 창이다. 주 창이 소유자라 주 창을 내리면 같이 내려가고, 주 창 위에 뜬다.
 * 그러면서도 주 창을 막지 않는다 — 패킷을 보면서 연결 / 해제를 누를 수 있어야 한다. */
void CDiagDlg::Open(CWnd *owner)
{
	if (!GetSafeHwnd()) {
		if (!Create(IDD_DIAG, owner)) {
			return;
		}
	}

	if (IsIconic()) {
		ShowWindow(SW_RESTORE);
	}
	ShowWindow(SW_SHOW);
	SetForegroundWindow();
	SetTimer(DIAG_TIMER_ID, DIAG_TIMER_MS, nullptr);

	/* 숨어 있던 동안 쌓인 것을 한 번에 따라잡는다. */
	RefreshPacketCount();
	UpdateStats();
}

bool CDiagDlg::IsOpen() const
{
	return GetSafeHwnd() != nullptr && IsWindowVisible();
}

/* 닫기(X, Esc)는 숨기기다. 데이터는 주 창에 있으므로 창을 부술 이유가 없고, 부수면
 * 다시 열 때 필터와 선택이 사라진다. 숨긴 동안은 타이머도 멈춘다. */
void CDiagDlg::OnCancel()
{
	KillTimer(DIAG_TIMER_ID);
	ShowWindow(SW_HIDE);
}

/* 리스트에서 친 Enter 가 창을 닫지 않게. */
void CDiagDlg::OnOK()
{
}

BOOL CDiagDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(AfxGetApp()->LoadIcon(IDI_APP), TRUE);
	SetIcon(static_cast<HICON>(LoadImageW(AfxGetInstanceHandle(), MAKEINTRESOURCEW(IDI_APP),
			IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
			LR_SHARED)), FALSE);
	ui::MatchTitleBar(GetSafeHwnd());

	ui::CreateFonts(reinterpret_cast<HFONT>(SendMessage(WM_GETFONT)), &m_fonts);
	m_card_brush.CreateSolidBrush(ui::Colors().card);

	m_tabs = ::GetDlgItem(GetSafeHwnd(), IDC_TAB);
	ui::TabsAdd(m_tabs, L"패킷");
	ui::TabsAdd(m_tabs, L"로그");

	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_CLEAR), ui::BUTTON_SECONDARY);
	ui::StyleButton(::GetDlgItem(GetSafeHwnd(), IDC_SAVE), ui::BUTTON_SECONDARY);

	CComboBox *filter = (CComboBox *)GetDlgItem(IDC_FILTER_DIR);
	filter->AddString(_T("전체"));
	filter->AddString(_T("송신만"));
	filter->AddString(_T("수신만"));
	filter->SetCurSel(PKT_FILTER_ALL);

	SetupPacketColumns();

	/* 가상 리스트: 행을 컨트롤에 복사하지 않고 그릴 때마다 LVN_GETDISPINFO 로
	 * 물어본다. 수만 행이 되어도 컨트롤 쪽 메모리와 삽입 비용이 늘지 않는다.
	 * DOUBLEBUFFER 는 빠르게 추가될 때의 깜빡임을 없앤다. */
	m_packets.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
			LVS_EX_HEADERDRAGDROP);
	StyleList(m_packets);

	m_detail.SetFont(CFont::FromHandle(m_fonts.mono));
	m_log.SetFont(CFont::FromHandle(m_fonts.mono));

	/* 창이 없던 동안 쌓인 로그 */
	for (const CString &line : m_logLines) {
		m_log.AddString(line);
	}
	m_log.SetTopIndex(m_log.GetCount() - 1);

	ApplyFilter();
	UpdateStats();
	OnTabChanged();

	return TRUE;
}

/* 리스트를 탐색기와 같은 모양으로 (선택 / 마우스 올림 표시가 납작해진다) 바꾸고 행을
 * 조금 높인다. 리스트뷰에는 행 높이를 정하는 설정이 없다. 행은 글꼴과 작은 아이콘
 * 중 큰 쪽에 맞춰지므로, 높이만 있는 빈 이미지 목록을 물려 준다. */
void CDiagDlg::StyleList(CListCtrl &list)
{
	SetWindowTheme(list.GetSafeHwnd(), L"Explorer", nullptr);

	if (!m_row_pad.GetSafeHandle()) {
		m_row_pad.Create(1, ui::Scale(22), ILC_COLOR32, 0, 1);
	}
	list.SetImageList(&m_row_pad, LVSIL_SMALL);
}

void CDiagDlg::SetupPacketColumns()
{
	CRect unit(0, 0, 4, 8);
	MapDialogRect(&unit);

	for (int i = 0; i < COLUMN_COUNT; i++) {
		int px = COLUMNS[i].du_width * unit.Width() / 4;
		m_packets.InsertColumn(i, COLUMNS[i].title, COLUMNS[i].format, px);
	}
}

/* ---- 주 창이 알려 주는 것 ---------------------------------------------- */
void CDiagDlg::PacketsChanged()
{
	if (IsOpen()) {
		RefreshPacketCount();
	}
}

void CDiagDlg::LogAppended(const CString &line)
{
	if (GetSafeHwnd()) {
		AddLogLine(line);
	}
}

void CDiagDlg::AddLogLine(const CString &line)
{
	if (m_log.AddString(line) < 0) {
		return;
	}
	while (m_log.GetCount() > LOG_MAX_LINES) {
		m_log.DeleteString(0);
	}
	m_log.SetTopIndex(m_log.GetCount() - 1);
}

/* ---- 버튼 -------------------------------------------------------------- */
void CDiagDlg::OnClear()
{
	m_store.Clear();
	m_logLines.clear();
	m_log.ResetContent();
	m_detail.SetWindowText(_T(""));
	RefreshPacketCount();
	UpdateStats();
}

void CDiagDlg::OnSave()
{
	CFileDialog dlg(FALSE, _T("csv"), _T("ztgate_packets.csv"),
			OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST,
			_T("CSV 파일 (*.csv)|*.csv|모든 파일 (*.*)|*.*||"), this);

	if (dlg.DoModal() != IDOK) {
		return;
	}

	CStdioFile f;
	if (!f.Open(dlg.GetPathName(), CFile::modeCreate | CFile::modeWrite | CFile::typeBinary)) {
		AfxMessageBox(_T("파일을 열 수 없습니다."), MB_ICONERROR);
		return;
	}

	try {
		/* 엑셀이 한글을 알아보게 UTF-8 BOM 을 먼저 쓴다. */
		const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
		f.Write(bom, 3);

		CString line;
		for (int c = 0; c < COLUMN_COUNT; c++) {
			line += COLUMNS[c].title;
			line += (c + 1 < COLUMN_COUNT) ? _T(",") : _T("\r\n");
		}

		CStringA utf8;
		int n = m_store.ViewCount();
		for (int i = -1; i < n; i++) {
			if (i >= 0) {
				const tunnel_packet_t *p = m_store.ViewAt(i);
				line.Empty();
				for (int c = 0; c < COLUMN_COUNT; c++) {
					CString v = pkt::ColumnText(*p, c);
					v.Replace(_T("\""), _T("\"\""));
					line += _T("\"") + v + _T("\"");
					line += (c + 1 < COLUMN_COUNT) ? _T(",") : _T("\r\n");
				}
			}

			int need = WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
			if (need > 1) {
				char *buf = utf8.GetBufferSetLength(need);
				WideCharToMultiByte(CP_UTF8, 0, line, -1, buf, need, nullptr, nullptr);
				f.Write(buf, (UINT)(need - 1));
			}
		}
		f.Close();
	}
	catch (CFileException *e) {
		e->Delete();
		AfxMessageBox(_T("저장 중 오류가 발생했습니다."), MB_ICONERROR);
		return;
	}

	CString done = _T("[gui] 저장 완료: ") + dlg.GetPathName();
	m_logLines.push_back(done);
	AddLogLine(done);
}

void CDiagDlg::OnFilterChanged()
{
	ApplyFilter();
}

void CDiagDlg::ApplyFilter()
{
	CComboBox *filter = (CComboBox *)GetDlgItem(IDC_FILTER_DIR);
	int dir = filter ? filter->GetCurSel() : PKT_FILTER_ALL;

	if (dir < 0) {
		dir = PKT_FILTER_ALL;
	}

	m_store.SetFilter(dir,
			IsDlgButtonChecked(IDC_HIDE_KA) == BST_CHECKED,
			IsDlgButtonChecked(IDC_ONLY_DROPS) == BST_CHECKED);

	m_detail.SetWindowText(_T(""));
	RefreshPacketCount();
}

void CDiagDlg::RefreshPacketCount()
{
	if (!m_packets.GetSafeHwnd()) {
		return;
	}

	int n = m_store.ViewCount();

	/* 가상 리스트는 "몇 행인지"만 알려주면 된다. */
	m_packets.SetItemCountEx(n, LVSICF_NOSCROLL | LVSICF_NOINVALIDATEALL);
	m_packets.Invalidate(FALSE);

	/* 선택이 없으면 최신 행을 따라간다. 사용자가 뭔가 골라 보고 있으면 건드리지 않는다. */
	if (n > 0 && m_packets.GetSelectedCount() == 0) {
		m_packets.EnsureVisible(n - 1, FALSE);
	}
}

/* ---- 가상 리스트 ------------------------------------------------------- */
void CDiagDlg::OnGetDispInfo(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLVDISPINFO *di = reinterpret_cast<NMLVDISPINFO *>(pNMHDR);

	*pResult = 0;

	if (!(di->item.mask & LVIF_TEXT)) {
		return;
	}

	const tunnel_packet_t *p = m_store.ViewAt(di->item.iItem);
	if (!p) {
		di->item.pszText[0] = _T('\0');
		return;
	}

	CString s = pkt::ColumnText(*p, di->item.iSubItem);
	_tcsncpy_s(di->item.pszText, di->item.cchTextMax, s, _TRUNCATE);
}

/* 행 전체를 방향별로 칠하지 않는다. 표가 줄무늬로 가득 차면 정작 봐야 할 폐기 행이
 * 묻힌다. 방향은 그 열의 글자색으로만 알리고, 바탕을 칠하는 것은 폐기된 행뿐이다. */
void CDiagDlg::OnPacketCustomDraw(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVCUSTOMDRAW cd = reinterpret_cast<LPNMLVCUSTOMDRAW>(pNMHDR);
	const ui::Palette &c = ui::Colors();

	*pResult = CDRF_DODEFAULT;

	/* 고대비에서는 시스템이 고른 색을 그대로 둔다. 폐기 여부는 결과 열에 글자로 있다. */
	if (c.highContrast) {
		return;
	}

	switch (cd->nmcd.dwDrawStage) {
	case CDDS_PREPAINT:
		*pResult = CDRF_NOTIFYITEMDRAW;
		return;

	case CDDS_ITEMPREPAINT:
		*pResult = CDRF_NOTIFYSUBITEMDRAW;
		return;

	case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
		const tunnel_packet_t *p = m_store.ViewAt((int)cd->nmcd.dwItemSpec);

		if (!p) {
			return;
		}

		if (p->verdict == TUNNEL_DROP_NON_UNICAST || p->verdict == TUNNEL_DROP_NON_IPV4) {
			/* Windows 가 터널 어댑터로도 늘 내보내는 멀티캐스트 / IPv6 를 거른 것이다.
			 * 정상 동작이라 빨갛게 칠하면 진짜 문제(위조, 재전송, 거부)가 묻힌다. */
			cd->clrTextBk = c.card;
			cd->clrText = c.idle;
		}
		else if (p->verdict != TUNNEL_PASS) {
			cd->clrTextBk = c.dangerBg;
			cd->clrText = c.danger;
		}
		else {
			cd->clrTextBk = c.card;
			if (cd->iSubItem == pkt::COL_DIR) {
				cd->clrText = (p->dir == TUNNEL_DIR_TX) ? c.tx : c.rx;
			}
			else if (cd->iSubItem == pkt::COL_SUMMARY || cd->iSubItem == pkt::COL_TYPE) {
				cd->clrText = c.text;
			}
			else {
				/* 번호, 시간, 세션, counter, 길이, 결과는 한 단계 흐리게. 눈이
				 * 타입과 요약으로 먼저 간다. */
				cd->clrText = c.muted;
			}
		}
		*pResult = CDRF_NEWFONT;
		return;
	}
	default:
		return;
	}
}

/* 리스트가 비어 있을 때 한가운데에 보일 글. 빈 표만 있으면 고장인지 아직 아무 일도
 * 없었던 것인지 알 수 없다. */
void CDiagDlg::OnGetEmptyMarkup(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLVEMPTYMARKUP *em = reinterpret_cast<NMLVEMPTYMARKUP *>(pNMHDR);

	em->dwFlags = EMF_CENTERED;
	wcsncpy_s(em->szMarkup, ARRAYSIZE(em->szMarkup),
			L"표시할 패킷이 없습니다. 연결하면 터널을 오가는 패킷이 여기에 나타납니다.", _TRUNCATE);
	*pResult = TRUE;
}

void CDiagDlg::OnPacketSelChanged(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLISTVIEW *lv = reinterpret_cast<NMLISTVIEW *>(pNMHDR);

	*pResult = 0;

	if ((lv->uChanged & LVIF_STATE) && (lv->uNewState & LVIS_SELECTED)) {
		ShowDetail(lv->iItem);
	}
}

void CDiagDlg::ShowDetail(int viewIndex)
{
	const tunnel_packet_t *p = m_store.ViewAt(viewIndex);

	m_detail.SetWindowText(p ? pkt::DetailText(*p) : CString());
}

/* 탭마다 필요한 것만 보인다. 필터와 상세창은 패킷에만 뜻이 있으므로 로그 탭에서는
 * 치우고 그 자리를 내용에 준다. */
void CDiagDlg::OnTabChanged()
{
	static const int packetsOnly[] = { IDC_FILTER_DIR, IDC_HIDE_KA, IDC_ONLY_DROPS, IDC_SAVE, IDC_DETAIL };
	const int sel = ui::TabsGetSel(m_tabs);
	CRect rc;

	m_packets.ShowWindow(sel == DIAG_TAB_PACKETS ? SW_SHOW : SW_HIDE);
	m_log.ShowWindow(sel == DIAG_TAB_LOG ? SW_SHOW : SW_HIDE);

	for (int id : packetsOnly) {
		GetDlgItem(id)->ShowWindow(sel == DIAG_TAB_PACKETS ? SW_SHOW : SW_HIDE);
	}

	GetClientRect(&rc);
	LayoutChildren(rc.Width(), rc.Height());
}

/* ---- 통계 -------------------------------------------------------------- */
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

/* 숫자는 타일에, 폐기 사유의 내역은 맨 아래 한 줄에 둔다. 사유는 0 이 아닌 것만 적는다.
 * 일곱 가지를 늘 다 적어 두면 대부분 0 인 숫자 사이에서 하나 있는 2 를 찾아야 한다. */
void CDiagDlg::UpdateStats()
{
	static const struct {
		int verdict;
		LPCTSTR name;
	} reasons[] = {
		{ TUNNEL_DROP_DENIED,		_T("접근 거부") },
		{ TUNNEL_DROP_BAD_TAG,		_T("위조 / 손상") },
		{ TUNNEL_DROP_REPLAY,		_T("재전송") },
		{ TUNNEL_DROP_NON_UNICAST,	_T("비유니캐스트") },
		{ TUNNEL_DROP_WRONG_SESSION,	_T("세션 불일치") },
		{ TUNNEL_DROP_NOT_SERVER,	_T("서버 아닌 출발지") },
		{ TUNNEL_DROP_BAD_HEADER,	_T("헤더 불량") },
		{ TUNNEL_DROP_NON_IPV4,		_T("IPv4 아님") },
		{ TUNNEL_DROP_TOO_LONG,		_T("길이 초과") },
		{ TUNNEL_DROP_UNKNOWN_TYPE,	_T("알 수 없는 타입") },
		{ TUNNEL_DROP_IO_ERROR,		_T("전달 실패") },
	};
	const PacketStats &st = m_store.Stats();
	CString value[TILE_COUNT];
	CString note[TILE_COUNT];
	CString footer;
	CString t;

	value[TILE_TX].Format(_T("%llu"), st.tx_packets);
	note[TILE_TX] = BytesText(st.tx_bytes);
	value[TILE_RX].Format(_T("%llu"), st.rx_packets);
	note[TILE_RX] = BytesText(st.rx_bytes);
	value[TILE_KEEPALIVE].Format(_T("%llu / %llu"), st.ka_sent, st.ka_recv);
	note[TILE_KEEPALIVE] = _T("보냄 / 받음");
	value[TILE_DROPS].Format(_T("%llu"), m_store.TotalDrops());
	value[TILE_REHANDSHAKE].Format(_T("%llu"), st.rehandshakes);

	footer.Format(_T("패킷 %d개 표시"), m_store.ViewCount());
	for (const auto &r : reasons) {
		if (st.drops[r.verdict] != 0) {
			t.Format(_T("%s%s %llu"), note[TILE_DROPS].IsEmpty() ? _T("") : _T(", "),
					r.name, st.drops[r.verdict]);
			note[TILE_DROPS] += t;
		}
	}
	if (!note[TILE_DROPS].IsEmpty()) {
		footer += _T("   ·   폐기 사유: ") + note[TILE_DROPS];
		/* 타일은 좁다. 내역은 아래 줄에서 읽는다. */
		note[TILE_DROPS] = _T("내역은 아래 줄");
	}
	if (st.lost) {
		t.Format(_T("   ·   화면이 따라가지 못해 놓친 패킷 %llu"), st.lost);
		footer += t;
	}

	for (int i = 0; i < TILE_COUNT; i++) {
		if (value[i] != m_tile_value[i] || note[i] != m_tile_note[i]) {
			m_tile_value[i] = value[i];
			m_tile_note[i] = note[i];
			if (!m_rc_tiles[i].IsRectEmpty()) {
				InvalidateRect(&m_rc_tiles[i], FALSE);
			}
		}
	}
	if (footer != m_footer) {
		m_footer = footer;
		if (!m_rc_footer.IsRectEmpty()) {
			InvalidateRect(&m_rc_footer, FALSE);
		}
	}
}

void CDiagDlg::OnTimer(UINT_PTR id)
{
	if (id == DIAG_TIMER_ID) {
		UpdateStats();
	}

	CDialogEx::OnTimer(id);
}

/* ---- 그리기 ------------------------------------------------------------ */

/* 라벨과 체크 상자는 스스로 그리되 바탕색을 부모에게 묻는다. 모두 흰 판 위에 있으므로
 * 판의 색을 준다. */
HBRUSH CDiagDlg::OnCtlColor(CDC *pDC, CWnd *pWnd, UINT type)
{
	if (type == CTLCOLOR_STATIC || type == CTLCOLOR_BTN) {
		pDC->SetBkColor(ui::Colors().card);
		pDC->SetTextColor(ui::Colors().text);

		return static_cast<HBRUSH>(m_card_brush.GetSafeHandle());
	}

	return CDialogEx::OnCtlColor(pDC, pWnd, type);
}

/* 바탕은 OnPaint 가 한 번에 그린다. 여기서 먼저 지우면 지운 색이 잠깐 보인다. */
BOOL CDiagDlg::OnEraseBkgnd(CDC *)
{
	return TRUE;
}

/* 테마가 입혀진 체크 상자는 자기 뒤의 바탕을 부모에게 그려 달라고 한다. */
LRESULT CDiagDlg::OnPrintClient(WPARAM wParam, LPARAM)
{
	PaintBackground(reinterpret_cast<HDC>(wParam));

	return 0;
}

/* 화면 밖 비트맵에 다 그린 뒤 한 번에 옮긴다. 통계가 초마다 바뀌는데 바로 그리면
 * 지우고 쓰는 사이가 깜빡임으로 보인다. */
void CDiagDlg::OnPaint()
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

void CDiagDlg::PaintTile(HDC dc, int tile)
{
	static const LPCTSTR labels[TILE_COUNT] = {
		_T("송신"), _T("수신"), _T("keepalive"), _T("폐기"), _T("재핸드셰이크"),
	};
	const ui::Palette &c = ui::Colors();
	const CRect &rc = m_rc_tiles[tile];
	const int pad = ui::Scale(12);
	COLORREF valueColor = c.text;
	CRect line;
	SIZE size;

	if (rc.IsRectEmpty()) {
		return;
	}

	ui::RoundRect(dc, rc, ui::Scale(6), c.card, c.border);

	/* 재핸드셰이크만 색을 쓴다. 폐기는 대부분 Windows 가 터널 어댑터로도 내보내는
	 * 멀티캐스트 / IPv6 라 늘 0 이 아니고, 그것을 빨갛게 칠하면 고장처럼 보인다. 무엇이
	 * 폐기됐는지는 아래 줄에 사유별로 있다. */
	if (tile == TILE_REHANDSHAKE && m_tile_value[tile] != _T("0")) {
		valueColor = c.warn;
	}

	line.SetRect(rc.left + pad, rc.top + ui::Scale(7), rc.right - pad, rc.top + rc.Height() / 2);
	ui::Text(dc, line, labels[tile], m_fonts.label, c.muted, DT_LEFT | DT_TOP | DT_SINGLELINE);

	line.SetRect(rc.left + pad, rc.top + rc.Height() / 2 - ui::Scale(4), rc.right - pad, rc.bottom - ui::Scale(6));
	ui::Text(dc, line, m_tile_value[tile], m_fonts.value, valueColor,
			DT_LEFT | DT_BOTTOM | DT_SINGLELINE);

	/* 보조 설명은 숫자 오른쪽 아래에 맞춘다. 자리가 모자라면 그리지 않는다. */
	size = ui::Measure(dc, m_tile_value[tile], m_fonts.value);
	line.left += size.cx + ui::Scale(8);
	if (!m_tile_note[tile].IsEmpty() &&
			ui::Measure(dc, m_tile_note[tile], m_fonts.label).cx <= line.Width()) {
		line.bottom -= ui::Scale(3);
		ui::Text(dc, line, m_tile_note[tile], m_fonts.label, c.muted,
				DT_LEFT | DT_BOTTOM | DT_SINGLELINE);
	}
}

/* 컨트롤이 아닌 모든 것. 좌표는 LayoutChildren 이 정해 둔 것을 그대로 쓴다. */
void CDiagDlg::PaintBackground(HDC dc)
{
	const ui::Palette &c = ui::Colors();
	const int radius = ui::Scale(8);
	CRect client;
	CRect rc;
	HBRUSH brush;

	GetClientRect(&client);
	brush = CreateSolidBrush(c.bg);
	FillRect(dc, &client, brush);
	DeleteObject(brush);

	for (int i = 0; i < TILE_COUNT; i++) {
		PaintTile(dc, i);
	}

	/* 내용: 탭 줄 + 리스트 */
	if (!m_rc_content.IsRectEmpty()) {
		ui::RoundRect(dc, m_rc_content, radius, c.card, c.border);

		rc.SetRect(m_rc_content.left + 1, m_sep_y, m_rc_content.right - 1, m_sep_y + 1);
		brush = CreateSolidBrush(c.border);
		FillRect(dc, &rc, brush);
		DeleteObject(brush);
	}

	/* 선택한 패킷 */
	if (!m_rc_detail.IsRectEmpty()) {
		ui::RoundRect(dc, m_rc_detail, radius, c.card, c.border);

		rc.SetRect(m_rc_detail.left + ui::Scale(14), m_rc_detail.top + ui::Scale(8),
				m_rc_detail.right - ui::Scale(14), m_rc_detail.top + ui::Scale(28));
		ui::Text(dc, rc, _T("선택한 패킷"), m_fonts.strong, c.muted,
				DT_LEFT | DT_TOP | DT_SINGLELINE);
	}

	if (!m_rc_footer.IsRectEmpty()) {
		ui::Text(dc, m_rc_footer, m_footer, m_fonts.label, c.muted,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
	}
}

/* 버튼은 ui_controls 가 그린다. */
void CDiagDlg::OnDrawItem(int id, LPDRAWITEMSTRUCT dis)
{
	if (ui::DrawButton(dis)) {
		return;
	}

	CDialogEx::OnDrawItem(id, dis);
}

void CDiagDlg::OnSysColorChange()
{
	CDialogEx::OnSysColorChange();

	/* 이 창도 최상위 창이라 주 창과 따로 이 메시지를 받는다. 어느 쪽이 먼저 받을지
	 * 모르므로 각자 색을 다시 정한다 (같은 값이 나온다). */
	ui::RefreshPalette();
	m_card_brush.DeleteObject();
	m_card_brush.CreateSolidBrush(ui::Colors().card);
	ui::MatchTitleBar(GetSafeHwnd());
	RedrawWindow(nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

/* ---- 레이아웃 ---------------------------------------------------------- */
void CDiagDlg::OnGetMinMaxInfo(MINMAXINFO *mmi)
{
	CRect rc(0, 0, 480, 300);

	MapDialogRect(&rc);
	/* 클라이언트 크기 기준이라 테두리 / 캡션을 더해 준다. */
	AdjustWindowRectEx(&rc, GetStyle(), FALSE, GetExStyle());

	mmi->ptMinTrackSize.x = rc.Width();
	mmi->ptMinTrackSize.y = rc.Height();

	CDialogEx::OnGetMinMaxInfo(mmi);
}

void CDiagDlg::OnSize(UINT type, int cx, int cy)
{
	CDialogEx::OnSize(type, cx, cy);

	if (type != SIZE_MINIMIZED) {
		LayoutChildren(cx, cy);
	}
}

/*  [ 송신 ]   [ 수신 ]   [ keepalive ]   [ 폐기 ]   [ 재핸드셰이크 ]    타일
 *  +--------------------------------------------------------------+
 *  | 패킷  로그                  [전체▾] □ □        [지움] [저장] |  내용
 *  |--------------------------------------------------------------|
 *  | 리스트                                                       |
 *  +--------------------------------------------------------------+
 *  | 선택한 패킷 (패킷 탭에서만)                                   |
 *  +--------------------------------------------------------------+
 *   패킷 N개 표시 · 폐기 사유: ...                                    바닥
 */
void CDiagDlg::LayoutChildren(int cx, int cy)
{
	/* OnSize 는 컨트롤이 만들어지기 전에도 올 수 있다. */
	if (!m_packets.GetSafeHwnd() || !m_tabs) {
		return;
	}

	CRect unit(0, 0, 4, 8);
	MapDialogRect(&unit);
	const int ux = unit.Width();
	const int uy = unit.Height();

	/* 다이얼로그 단위 -> 픽셀. .rc 와 같은 숫자를 쓸 수 있어 읽기 쉽다. */
	auto DX = [ux](int du) { return du * ux / 4; };
	auto DY = [uy](int du) { return du * uy / 8; };

	const int sel = ui::TabsGetSel(m_tabs);
	const int m = DX(8);
	const int gap = DY(6);

	const int tilesTop = DY(7);
	const int tilesH = DY(34);
	const int tileGap = DX(6);
	const int tileW = (cx - 2 * m - (TILE_COUNT - 1) * tileGap) / TILE_COUNT;

	for (int i = 0; i < TILE_COUNT; i++) {
		const int x = m + i * (tileW + tileGap);

		/* 나눗셈의 나머지는 마지막 타일이 가져가 오른쪽 끝을 맞춘다. */
		m_rc_tiles[i].SetRect(x, tilesTop, (i == TILE_COUNT - 1) ? cx - m : x + tileW, tilesTop + tilesH);
	}

	const int footerH = DY(10);
	m_rc_footer.SetRect(m + DX(4), cy - DY(4) - footerH, cx - m, cy - DY(4));

	int contentBottom = m_rc_footer.top - DY(4);

	if (sel == DIAG_TAB_PACKETS) {
		const int detailH = DY(86);

		m_rc_detail.SetRect(m, contentBottom - detailH, cx - m, contentBottom);
		contentBottom = m_rc_detail.top - gap;
	}
	else {
		m_rc_detail.SetRectEmpty();
	}
	m_rc_content.SetRect(m, tilesTop + tilesH + gap, cx - m, contentBottom);

	/* 여러 컨트롤을 한 번에 옮긴다. 하나씩 MoveWindow 하면 중간 상태가 그려져 깜빡인다. */
	HDWP dwp = BeginDeferWindowPos(12);
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

	/* 내용의 윗줄: 왼쪽에 탭, 오른쪽에 그 탭의 도구 */
	const int rowTop = m_rc_content.top + DY(3);
	const int rowH = DY(18);
	const int toolH = DY(14);
	const int toolY = rowTop + (rowH - toolH) / 2;
	int tabsW = ui::TabsIdealWidth(m_tabs);
	int x = m_rc_content.right - DX(8);

	if (tabsW <= 0) {
		tabsW = DX(100);
	}
	Place(IDC_TAB, m_rc_content.left + DX(4), rowTop, tabsW, rowH);
	m_sep_y = rowTop + rowH + DY(2);

	x -= DX(42);
	Place(IDC_SAVE, x, toolY, DX(42), toolH);
	if (sel != DIAG_TAB_PACKETS) {
		x += DX(42);	/* 저장이 없는 탭에서는 지움이 끝으로 온다 */
	}
	else {
		x -= DX(4);
	}
	x -= DX(36);
	Place(IDC_CLEAR, x, toolY, DX(36), toolH);

	x -= DX(12) + DX(44);
	Place(IDC_ONLY_DROPS, x, rowTop + (rowH - DY(10)) / 2, DX(44), DY(10));
	x -= DX(4) + DX(76);
	Place(IDC_HIDE_KA, x, rowTop + (rowH - DY(10)) / 2, DX(76), DY(10));
	x -= DX(8) + DX(52);
	/* 콤보 상자의 높이는 펼쳤을 때의 높이다. */
	Place(IDC_FILTER_DIR, x, rowTop + (rowH - DY(13)) / 2, DX(52), DY(80));

	/* 리스트는 판의 둥근 모서리를 덮지 않게 조금 들여 넣는다. */
	const int listX = m_rc_content.left + DX(2);
	const int listY = m_sep_y + 1;
	const int listW = m_rc_content.Width() - 2 * DX(2);
	const int listH = m_rc_content.bottom - DY(4) - listY;

	Place(IDC_PACKETS, listX, listY, listW, listH);
	Place(IDC_LOG, listX + DX(4), listY + DY(2), listW - DX(4), listH - DY(2));

	if (!m_rc_detail.IsRectEmpty()) {
		Place(IDC_DETAIL, m_rc_detail.left + DX(8), m_rc_detail.top + DY(16),
				m_rc_detail.Width() - 2 * DX(8), m_rc_detail.Height() - DY(20));
	}

	EndDeferWindowPos(dwp);

	/* 요약 열이 남는 폭을 가져간다. 창을 넓혀도 오른쪽에 빈 칸만 늘지 않게. */
	CRect client;
	m_packets.GetClientRect(&client);
	int others = 0;
	for (int i = 0; i < COLUMN_COUNT; i++) {
		if (i != pkt::COL_SUMMARY) {
			others += m_packets.GetColumnWidth(i);
		}
	}
	m_packets.SetColumnWidth(pkt::COL_SUMMARY, max(DX(COLUMNS[pkt::COL_SUMMARY].du_width), client.Width() - others));

	/* 판의 자리가 바뀌었으니 바탕을 다시 그린다. */
	Invalidate(FALSE);
}

void CDiagDlg::OnDestroy()
{
	KillTimer(DIAG_TIMER_ID);

	CDialogEx::OnDestroy();

	/* 컨트롤이 쓰던 글꼴은 컨트롤이 사라진 뒤에 지운다. */
	ui::DestroyFonts(&m_fonts);
}
