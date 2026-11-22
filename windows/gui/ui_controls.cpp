#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include <string>
#include <vector>

#include "ui_theme.h"
#include "ui_controls.h"

#ifdef _MSC_VER
#pragma comment(lib, "comctl32.lib")
#endif

namespace ui {

/* ---- 버튼 ---------------------------------------------------------------- */

struct ButtonData {
	ButtonKind kind;
	bool hover;
	bool isDefault;		/* 지금 Enter 를 받는 버튼인가 */
};

#define BUTTON_SUBCLASS_ID 1

static LRESULT CALLBACK ButtonProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
		UINT_PTR id, DWORD_PTR ref)
{
	ButtonData *data = reinterpret_cast<ButtonData *>(ref);

	switch (msg) {
	case WM_MOUSEMOVE:
		/* 소유자 그리기 버튼은 마우스가 올라왔는지 알려 주지 않는다. 직접 쫓는다.
		 * TrackMouseEvent 는 한 번 알리면 끝이라 들어올 때마다 다시 건다. */
		if (!data->hover) {
			TRACKMOUSEEVENT tme;

			tme.cbSize = sizeof(tme);
			tme.dwFlags = TME_LEAVE;
			tme.hwndTrack = hwnd;
			tme.dwHoverTime = 0;
			TrackMouseEvent(&tme);

			data->hover = true;
			InvalidateRect(hwnd, nullptr, FALSE);
		}
		break;

	case WM_MOUSELEAVE:
		data->hover = false;
		InvalidateRect(hwnd, nullptr, FALSE);
		break;

	case WM_LBUTTONDBLCLK:
		/* 소유자 그리기 버튼은 빠르게 두 번 누르면 두 번째를 "더블클릭"으로 보고
		 * 눌림 처리를 하지 않는다. 연결 / 해제를 빠르게 누르면 한 번이 사라진다. */
		msg = WM_LBUTTONDOWN;
		break;

	case WM_ERASEBKGND:
		/* 전부 WM_DRAWITEM 에서 칠한다. 여기서 지우면 깜빡인다. */
		return 1;

	/* 다이얼로그는 포커스가 버튼으로 옮겨 가면 그 버튼을 "기본 버튼"으로 만들어 Enter 를
	 * 받게 한다. 버튼에게 WM_GETDLGCODE 로 기본 버튼이 될 수 있는지 묻고, 될 수 있다면
	 * BM_SETSTYLE 로 BS_DEFPUSHBUTTON 을 준다. 소유자 그리기 버튼은 "될 수 없다"고
	 * 답하므로, 그대로 두면 [지움]에 포커스를 두고 Enter 를 쳐도 [연결]이 눌린다.
	 *
	 * 될 수 있다고 답하되 BM_SETSTYLE 은 우리가 받아 적기만 한다. 원래 처리에 넘기면
	 * 스타일의 종류 비트가 BS_DEFPUSHBUTTON 으로 덮여 BS_OWNERDRAW 가 사라진다. */
	case WM_GETDLGCODE:
		return DLGC_BUTTON | (data->isDefault ? DLGC_DEFPUSHBUTTON : DLGC_UNDEFPUSHBUTTON);

	case BM_SETSTYLE:
		data->isDefault = ((wParam & BS_TYPEMASK) == BS_DEFPUSHBUTTON);
		return 0;

	case WM_NCDESTROY:
		RemoveWindowSubclass(hwnd, ButtonProc, id);
		delete data;
		break;
	}

	return DefSubclassProc(hwnd, msg, wParam, lParam);
}

static ButtonData *GetButtonData(HWND button)
{
	DWORD_PTR ref = 0;

	if (!GetWindowSubclass(button, ButtonProc, BUTTON_SUBCLASS_ID, &ref)) {
		return nullptr;
	}

	return reinterpret_cast<ButtonData *>(ref);
}

void StyleButton(HWND button, ButtonKind kind)
{
	ButtonData *data;
	LONG_PTR style;

	if (button == nullptr || GetButtonData(button) != nullptr) {
		return;
	}

	style = GetWindowLongPtrW(button, GWL_STYLE);

	data = new ButtonData;
	data->kind = kind;
	data->hover = false;
	data->isDefault = ((style & BS_TYPEMASK) == BS_DEFPUSHBUTTON);

	if (!SetWindowSubclass(button, ButtonProc, BUTTON_SUBCLASS_ID, reinterpret_cast<DWORD_PTR>(data))) {
		delete data;
		return;
	}

	SetWindowLongPtrW(button, GWL_STYLE, (style & ~(LONG_PTR)BS_TYPEMASK) | BS_OWNERDRAW);
	InvalidateRect(button, nullptr, FALSE);
}

void SetButtonKind(HWND button, ButtonKind kind)
{
	ButtonData *data = button ? GetButtonData(button) : nullptr;

	if (data != nullptr && data->kind != kind) {
		data->kind = kind;
		InvalidateRect(button, nullptr, FALSE);
	}
}

bool DrawButton(const DRAWITEMSTRUCT *dis)
{
	const Palette &c = Colors();
	ButtonData *data;
	COLORREF fill, border, text;
	wchar_t label[64];
	RECT rc;
	HFONT font;
	bool pressed, disabled;

	if (dis == nullptr || dis->CtlType != ODT_BUTTON) {
		return false;
	}
	data = GetButtonData(dis->hwndItem);
	if (data == nullptr) {
		return false;
	}

	rc = dis->rcItem;
	pressed = (dis->itemState & ODS_SELECTED) != 0;
	disabled = (dis->itemState & ODS_DISABLED) != 0;

	/* 링크 버튼은 놓인 곳의 색을 바탕으로 쓴다. 창 바탕 위인지 판 위인지. */
	const bool link = data->kind == BUTTON_LINK || data->kind == BUTTON_CARD_LINK;
	const COLORREF under = data->kind == BUTTON_LINK ? c.bg : c.card;

	if (disabled) {
		/* 링크 버튼은 바탕 없이 글자만 흐리게. 상자가 생기면 눌러 볼 것처럼 보인다. */
		fill = link ? under : c.disabledFill;
		border = link ? CLR_NONE : c.border;
		text = c.disabledText;
	}
	else if (link) {
		fill = pressed ? c.buttonPressed : data->hover ? (data->kind == BUTTON_LINK ? c.border : c.bg) : under;
		border = CLR_NONE;
		text = (c.highContrast && (pressed || data->hover)) ? c.onAccent : c.accent;
	}
	else if (data->kind == BUTTON_PRIMARY) {
		fill = pressed ? c.accentPressed : data->hover ? c.accentHover : c.accent;
		border = CLR_NONE;
		text = c.onAccent;
	}
	else {
		fill = pressed ? c.buttonPressed : data->hover ? c.buttonHover : c.button;
		border = c.buttonBorder;
		text = (c.highContrast && (pressed || data->hover)) ? c.onAccent : c.text;
	}

	/* 둥근 모서리 바깥은 버튼이 놓인 곳의 색이다. 링크 버튼은 창 바탕에, 나머지는 판에. */
	{
		HBRUSH back = CreateSolidBrush(link ? under : c.card);

		FillRect(dis->hDC, &rc, back);
		DeleteObject(back);
	}
	RoundRect(dis->hDC, rc, Scale(4), fill, border);

	label[0] = L'\0';
	GetWindowTextW(dis->hwndItem, label, ARRAYSIZE(label));
	font = reinterpret_cast<HFONT>(SendMessageW(dis->hwndItem, WM_GETFONT, 0, 0));
	Text(dis->hDC, rc, label, font, text, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

	/* 키보드로 옮겨 다닐 때만 포커스를 보인다 (마우스로 누른 직후에는 시스템이
	 * ODS_NOFOCUSRECT 를 준다). */
	if ((dis->itemState & ODS_FOCUS) && !(dis->itemState & ODS_NOFOCUSRECT)) {
		RECT in = rc;

		InflateRect(&in, -Scale(2), -Scale(2));
		RoundRect(dis->hDC, in, Scale(3), CLR_NONE,
				data->kind == BUTTON_PRIMARY ? c.onAccent : c.text);
	}

	return true;
}

/* ---- 탭 줄 --------------------------------------------------------------- */

#define TABS_ADD	(WM_USER + 1)	/* lParam = LPCWSTR */
#define TABS_GETSEL	(WM_USER + 2)
#define TABS_IDEAL	(WM_USER + 4)

struct TabsData {
	std::vector<std::wstring> items;
	std::vector<RECT> rects;	/* 글자와 여백을 합친 클릭 영역 */
	int sel;
	int hot;
	bool tracking;
	HFONT font;	/* 부모가 WM_SETFONT 로 준 것 */
	HFONT strong;	/* 선택된 탭용. 우리가 만들고 지운다 */
};

static void TabsLayout(HWND hwnd, TabsData *d)
{
	const int padX = Scale(12);
	RECT client;
	HDC dc = GetDC(hwnd);
	int x = 0;

	GetClientRect(hwnd, &client);
	d->rects.clear();

	for (const std::wstring &item : d->items) {
		/* 선택되면 굵어지며 폭이 늘어난다. 굵은 쪽으로 재 두면 탭을 바꿔도
		 * 옆의 탭이 밀리지 않는다. */
		SIZE size = Measure(dc, item.c_str(), d->strong ? d->strong : d->font);
		RECT rc = { x, 0, x + size.cx + 2 * padX, client.bottom };

		d->rects.push_back(rc);
		x = rc.right;
	}

	if (dc) {
		ReleaseDC(hwnd, dc);
	}
}

static int TabsHitTest(const TabsData *d, int x, int y)
{
	POINT pt = { x, y };

	for (size_t i = 0; i < d->rects.size(); i++) {
		if (PtInRect(&d->rects[i], pt)) {
			return (int)i;
		}
	}

	return -1;
}

static void TabsSelect(HWND hwnd, TabsData *d, int index)
{
	if (index < 0 || index >= (int)d->items.size() || index == d->sel) {
		return;
	}

	d->sel = index;
	InvalidateRect(hwnd, nullptr, FALSE);

	SendMessageW(GetParent(hwnd), WM_COMMAND,
			MAKEWPARAM(GetDlgCtrlID(hwnd), UI_TABS_CHANGED),
			reinterpret_cast<LPARAM>(hwnd));
}

static void TabsPaint(HWND hwnd, TabsData *d)
{
	const Palette &c = Colors();
	PAINTSTRUCT ps;
	HDC paint = BeginPaint(hwnd, &ps);
	RECT client;
	HDC dc;
	HBITMAP bitmap;
	HGDIOBJ oldBitmap;
	HBRUSH back;

	GetClientRect(hwnd, &client);

	/* 화면 밖에서 다 그린 뒤 한 번에 옮긴다. 마우스를 움직일 때마다 다시 그리므로
	 * 바로 그리면 지우고 쓰는 사이가 보인다. */
	dc = CreateCompatibleDC(paint);
	bitmap = CreateCompatibleBitmap(paint, client.right, client.bottom);
	oldBitmap = SelectObject(dc, bitmap);

	back = CreateSolidBrush(c.card);
	FillRect(dc, &client, back);
	DeleteObject(back);

	for (size_t i = 0; i < d->items.size(); i++) {
		const bool selected = ((int)i == d->sel);
		const bool hot = ((int)i == d->hot);
		HFONT font = (selected && d->strong) ? d->strong : d->font;
		RECT rc = d->rects[i];

		Text(dc, rc, d->items[i].c_str(), font,
				(selected || hot) ? c.text : c.muted,
				DT_CENTER | DT_VCENTER | DT_SINGLELINE);

		if (selected) {
			/* 선택 표시는 글자 폭만큼의 밑줄이다. */
			SIZE size = Measure(dc, d->items[i].c_str(), font);
			const int mid = (rc.left + rc.right) / 2;
			RECT bar = { mid - size.cx / 2, rc.bottom - Scale(3), mid + size.cx / 2 + 1, rc.bottom };

			RoundRect(dc, bar, Scale(2), c.accent, CLR_NONE);

			if (GetFocus() == hwnd &&
					!(SendMessageW(hwnd, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS)) {
				RECT focus = rc;

				InflateRect(&focus, -Scale(4), -Scale(4));
				DrawFocusRect(dc, &focus);
			}
		}
	}

	BitBlt(paint, 0, 0, client.right, client.bottom, dc, 0, 0, SRCCOPY);

	SelectObject(dc, oldBitmap);
	DeleteObject(bitmap);
	DeleteDC(dc);
	EndPaint(hwnd, &ps);
}

static void TabsSetFont(HWND hwnd, TabsData *d, HFONT font)
{
	LOGFONTW lf;

	if (d->strong) {
		DeleteObject(d->strong);
		d->strong = nullptr;
	}

	d->font = font;
	if (font && GetObjectW(font, sizeof(lf), &lf)) {
		lf.lfWeight = FW_SEMIBOLD;
		d->strong = CreateFontIndirectW(&lf);
	}

	TabsLayout(hwnd, d);
}

static LRESULT CALLBACK TabsProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	TabsData *d = reinterpret_cast<TabsData *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

	if (msg == WM_NCCREATE) {
		d = new TabsData;
		d->sel = 0;
		d->hot = -1;
		d->tracking = false;
		d->font = nullptr;
		d->strong = nullptr;
		SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(d));

		return DefWindowProcW(hwnd, msg, wParam, lParam);
	}
	if (d == nullptr) {
		return DefWindowProcW(hwnd, msg, wParam, lParam);
	}

	switch (msg) {
	case WM_NCDESTROY:
		if (d->strong) {
			DeleteObject(d->strong);
		}
		SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
		delete d;
		break;

	case WM_PAINT:
		TabsPaint(hwnd, d);
		return 0;

	case WM_ERASEBKGND:
		return 1;

	case WM_SIZE:
		TabsLayout(hwnd, d);
		InvalidateRect(hwnd, nullptr, FALSE);
		return 0;

	case WM_SETFONT:
		TabsSetFont(hwnd, d, reinterpret_cast<HFONT>(wParam));
		InvalidateRect(hwnd, nullptr, FALSE);
		return 0;

	case WM_GETFONT:
		return reinterpret_cast<LRESULT>(d->font);

	case WM_GETDLGCODE:
		/* 방향키를 다이얼로그가 가져가 다음 컨트롤로 넘기지 않게 한다. */
		return DLGC_WANTARROWS;

	case WM_SETFOCUS:
	case WM_KILLFOCUS:
	case WM_UPDATEUISTATE:
		InvalidateRect(hwnd, nullptr, FALSE);
		break;

	case WM_KEYDOWN:
		if (wParam == VK_LEFT) {
			TabsSelect(hwnd, d, d->sel - 1);
			return 0;
		}
		if (wParam == VK_RIGHT) {
			TabsSelect(hwnd, d, d->sel + 1);
			return 0;
		}
		break;

	case WM_LBUTTONDOWN:
		SetFocus(hwnd);
		TabsSelect(hwnd, d, TabsHitTest(d, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)));
		return 0;

	case WM_MOUSEMOVE: {
		const int hot = TabsHitTest(d, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));

		if (!d->tracking) {
			TRACKMOUSEEVENT tme;

			tme.cbSize = sizeof(tme);
			tme.dwFlags = TME_LEAVE;
			tme.hwndTrack = hwnd;
			tme.dwHoverTime = 0;
			d->tracking = TrackMouseEvent(&tme) != FALSE;
		}
		if (hot != d->hot) {
			d->hot = hot;
			InvalidateRect(hwnd, nullptr, FALSE);
		}
		return 0;
	}

	case WM_MOUSELEAVE:
		d->tracking = false;
		if (d->hot != -1) {
			d->hot = -1;
			InvalidateRect(hwnd, nullptr, FALSE);
		}
		return 0;

	case TABS_ADD:
		d->items.push_back(reinterpret_cast<LPCWSTR>(lParam));
		TabsLayout(hwnd, d);
		InvalidateRect(hwnd, nullptr, FALSE);
		return 0;

	case TABS_GETSEL:
		return d->sel;

	case TABS_IDEAL:
		return d->rects.empty() ? 0 : d->rects.back().right;
	}

	return DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool RegisterTabs(HINSTANCE instance)
{
	WNDCLASSEXW wc;

	ZeroMemory(&wc, sizeof(wc));
	wc.cbSize = sizeof(wc);
	wc.lpfnWndProc = TabsProc;
	wc.hInstance = instance;
	wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	wc.lpszClassName = UI_TABS_CLASS;

	return RegisterClassExW(&wc) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

void TabsAdd(HWND tabs, LPCWSTR text)
{
	SendMessageW(tabs, TABS_ADD, 0, reinterpret_cast<LPARAM>(text));
}

int TabsGetSel(HWND tabs)
{
	return (int)SendMessageW(tabs, TABS_GETSEL, 0, 0);
}

int TabsIdealWidth(HWND tabs)
{
	return (int)SendMessageW(tabs, TABS_IDEAL, 0, 0);
}

} /* namespace ui */
