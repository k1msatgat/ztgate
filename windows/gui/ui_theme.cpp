#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include <dwmapi.h>

#include "ui_theme.h"

#ifdef _MSC_VER
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "dwmapi.lib")
#endif

/* SDK 가 오래되면 없다. 값은 Windows 11 SDK 의 dwmapi.h 와 같다. */
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif

namespace ui {

static Palette g_colors;
static ULONG_PTR g_gdiplus;

static Gdiplus::Color ToColor(COLORREF c)
{
	return Gdiplus::Color(255, GetRValue(c), GetGValue(c), GetBValue(c));
}

static bool HighContrastOn()
{
	HIGHCONTRASTW hc;

	ZeroMemory(&hc, sizeof(hc));
	hc.cbSize = sizeof(hc);

	return SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc), &hc, 0) &&
		(hc.dwFlags & HCF_HIGHCONTRASTON);
}

void RefreshPalette()
{
	Palette &c = g_colors;

	c.highContrast = HighContrastOn();

	if (c.highContrast) {
		/* 사용자가 고른 조합을 그대로 쓴다. 상태를 색으로만 구분하던 곳은 글자가
		 * 함께 있으므로(연결됨 / 거부됨, 전달 / 폐기 사유) 뜻이 사라지지 않는다. */
		c.bg = c.card = GetSysColor(COLOR_WINDOW);
		c.border = c.buttonBorder = GetSysColor(COLOR_WINDOWTEXT);
		c.text = c.muted = GetSysColor(COLOR_WINDOWTEXT);
		c.accent = c.accentHover = c.accentPressed = GetSysColor(COLOR_HIGHLIGHT);
		c.onAccent = GetSysColor(COLOR_HIGHLIGHTTEXT);
		c.button = c.disabledFill = c.dangerBg = GetSysColor(COLOR_WINDOW);
		c.buttonHover = c.buttonPressed = GetSysColor(COLOR_HIGHLIGHT);
		c.disabledText = GetSysColor(COLOR_GRAYTEXT);
		c.ok = c.warn = c.danger = c.idle = c.tx = c.rx = GetSysColor(COLOR_WINDOWTEXT);
		return;
	}

	/* docs/design/tokens.md 의 밝은 화면 색. 웹 콘솔과 같다. */
	c.bg = RGB(245, 247, 250);		/* bg #F5F7FA */
	c.card = RGB(255, 255, 255);
	c.border = RGB(220, 227, 236);		/* border #DCE3EC */
	c.text = RGB(26, 35, 51);		/* text #1A2333 */
	c.muted = RGB(91, 102, 120);		/* text-muted #5B6678 */

	c.accent = RGB(30, 78, 140);		/* accent #1E4E8C (네이비 블루) */
	c.accentHover = RGB(23, 63, 115);
	c.accentPressed = RGB(18, 51, 94);
	c.onAccent = RGB(255, 255, 255);

	c.button = RGB(255, 255, 255);
	c.buttonHover = RGB(238, 242, 247);	/* surface-2 */
	c.buttonPressed = RGB(226, 232, 240);
	c.buttonBorder = RGB(201, 211, 224);
	c.disabledText = RGB(160, 170, 186);
	c.disabledFill = RGB(238, 242, 247);

	c.ok = RGB(42, 157, 143);		/* teal #2A9D8F */
	c.warn = RGB(194, 124, 14);		/* warn #C27C0E */
	c.danger = RGB(180, 35, 47);		/* danger #B4232F */
	c.dangerBg = RGB(251, 233, 234);
	c.idle = RGB(138, 149, 168);		/* idle #8A95A8 */
	c.tx = RGB(30, 78, 140);
	c.rx = RGB(42, 157, 143);
}

const Palette &Colors()
{
	return g_colors;
}

void Startup()
{
	Gdiplus::GdiplusStartupInput in;

	if (g_gdiplus == 0) {
		Gdiplus::GdiplusStartup(&g_gdiplus, &in, nullptr);
	}
	RefreshPalette();
}

void Shutdown()
{
	if (g_gdiplus != 0) {
		Gdiplus::GdiplusShutdown(g_gdiplus);
		g_gdiplus = 0;
	}
}

static HFONT Derive(const LOGFONTW &base, int num, int den, LONG weight, LPCWSTR face)
{
	LOGFONTW lf = base;

	lf.lfHeight = MulDiv(base.lfHeight, num, den);
	lf.lfWidth = 0;
	lf.lfWeight = weight;
	if (face != nullptr) {
		lstrcpynW(lf.lfFaceName, face, LF_FACESIZE);
		lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
	}

	return CreateFontIndirectW(&lf);
}

/* 기호 글꼴. 글자 폭이 고정된 글꼴로 만들면 안 된다 (Derive 의 face 는 고정폭용). */
static HFONT DeriveSymbol(const LOGFONTW &base, int num, int den)
{
	LOGFONTW lf = base;

	lf.lfHeight = MulDiv(base.lfHeight, num, den);
	lf.lfWidth = 0;
	lf.lfWeight = FW_NORMAL;
	lf.lfCharSet = DEFAULT_CHARSET;
	lstrcpynW(lf.lfFaceName, L"Segoe MDL2 Assets", LF_FACESIZE);

	return CreateFontIndirectW(&lf);
}

void CreateFonts(HFONT dialogFont, Fonts *out)
{
	LOGFONTW lf;

	ZeroMemory(&lf, sizeof(lf));
	if (dialogFont == nullptr || GetObjectW(dialogFont, sizeof(lf), &lf) == 0) {
		NONCLIENTMETRICSW ncm;

		ZeroMemory(&ncm, sizeof(ncm));
		ncm.cbSize = sizeof(ncm);
		SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
		lf = ncm.lfMessageFont;
	}

	out->base = dialogFont;
	out->label = Derive(lf, 1, 1, FW_NORMAL, nullptr);
	out->strong = Derive(lf, 1, 1, FW_SEMIBOLD, nullptr);
	out->value = Derive(lf, 14, 9, FW_SEMIBOLD, nullptr);
	out->title = Derive(lf, 15, 9, FW_SEMIBOLD, nullptr);
	out->mono = Derive(lf, 1, 1, FW_NORMAL, L"Consolas");
	out->hero = Derive(lf, 18, 9, FW_SEMIBOLD, nullptr);
	out->icon = DeriveSymbol(lf, 24, 9);
	out->iconSmall = DeriveSymbol(lf, 9, 9);
}

void DestroyFonts(Fonts *fonts)
{
	HFONT *owned[] = { &fonts->label, &fonts->strong, &fonts->value, &fonts->title, &fonts->mono,
			   &fonts->hero, &fonts->icon, &fonts->iconSmall };

	for (HFONT *f : owned) {
		if (*f != nullptr) {
			DeleteObject(*f);
			*f = nullptr;
		}
	}
	fonts->base = nullptr;
}

int Scale(int px)
{
	static int dpi;

	/* 매니페스트가 "시스템 DPI 인식"이라 실행 중에는 바뀌지 않는다. */
	if (dpi == 0) {
		HDC dc = GetDC(nullptr);

		dpi = dc ? GetDeviceCaps(dc, LOGPIXELSX) : 96;
		if (dc) {
			ReleaseDC(nullptr, dc);
		}
	}

	return MulDiv(px, dpi, 96);
}

void RoundRect(HDC dc, const RECT &rc, int radius, COLORREF fill, COLORREF border)
{
	const int w = rc.right - rc.left;
	const int h = rc.bottom - rc.top;

	if (w <= 0 || h <= 0) {
		return;
	}

	/* 고대비에서는 곡선과 반투명 가장자리 없이 또렷한 선만 긋는다. */
	if (g_colors.highContrast || g_gdiplus == 0) {
		HBRUSH brush = (fill != CLR_NONE) ? CreateSolidBrush(fill) : nullptr;
		HPEN pen = (border != CLR_NONE) ? CreatePen(PS_SOLID, 1, border) : nullptr;
		HGDIOBJ oldBrush = SelectObject(dc, brush ? brush : GetStockObject(NULL_BRUSH));
		HGDIOBJ oldPen = SelectObject(dc, pen ? pen : GetStockObject(NULL_PEN));

		Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);

		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		if (brush) {
			DeleteObject(brush);
		}
		if (pen) {
			DeleteObject(pen);
		}
		return;
	}

	Gdiplus::Graphics g(dc);
	Gdiplus::GraphicsPath path;
	/* 1픽셀 펜은 좌표가 픽셀의 가운데(.5)에 있어야 번지지 않는다. */
	const Gdiplus::REAL x = (Gdiplus::REAL)rc.left + 0.5f;
	const Gdiplus::REAL y = (Gdiplus::REAL)rc.top + 0.5f;
	const Gdiplus::REAL rw = (Gdiplus::REAL)w - 1.0f;
	const Gdiplus::REAL rh = (Gdiplus::REAL)h - 1.0f;
	Gdiplus::REAL d = (Gdiplus::REAL)radius * 2.0f;

	if (d > rw) {
		d = rw;
	}
	if (d > rh) {
		d = rh;
	}

	g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

	if (d < 1.0f) {
		path.AddRectangle(Gdiplus::RectF(x, y, rw, rh));
	}
	else {
		path.AddArc(x, y, d, d, 180.0f, 90.0f);
		path.AddArc(x + rw - d, y, d, d, 270.0f, 90.0f);
		path.AddArc(x + rw - d, y + rh - d, d, d, 0.0f, 90.0f);
		path.AddArc(x, y + rh - d, d, d, 90.0f, 90.0f);
		path.CloseFigure();
	}

	if (fill != CLR_NONE) {
		Gdiplus::SolidBrush brush(ToColor(fill));
		g.FillPath(&brush, &path);
	}
	if (border != CLR_NONE) {
		Gdiplus::Pen pen(ToColor(border), 1.0f);
		g.DrawPath(&pen, &path);
	}
}

void Dot(HDC dc, int cx, int cy, int radius, COLORREF color)
{
	if (g_colors.highContrast || g_gdiplus == 0) {
		RECT rc = { cx - radius, cy - radius, cx + radius, cy + radius };
		HBRUSH brush = CreateSolidBrush(color);

		FillRect(dc, &rc, brush);
		DeleteObject(brush);
		return;
	}

	Gdiplus::Graphics g(dc);
	Gdiplus::SolidBrush brush(ToColor(color));

	g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
	g.FillEllipse(&brush, (Gdiplus::REAL)(cx - radius), (Gdiplus::REAL)(cy - radius),
			(Gdiplus::REAL)(radius * 2), (Gdiplus::REAL)(radius * 2));
}

void Text(HDC dc, const RECT &rc, LPCWSTR text, HFONT font, COLORREF color, UINT format)
{
	RECT r = rc;
	HGDIOBJ old = font ? SelectObject(dc, font) : nullptr;
	const int oldMode = SetBkMode(dc, TRANSPARENT);
	const COLORREF oldColor = SetTextColor(dc, color);

	DrawTextW(dc, text, -1, &r, format | DT_NOPREFIX);

	SetTextColor(dc, oldColor);
	SetBkMode(dc, oldMode);
	if (old) {
		SelectObject(dc, old);
	}
}

SIZE Measure(HDC dc, LPCWSTR text, HFONT font)
{
	SIZE size = { 0, 0 };
	HGDIOBJ old = font ? SelectObject(dc, font) : nullptr;

	GetTextExtentPoint32W(dc, text, lstrlenW(text), &size);

	if (old) {
		SelectObject(dc, old);
	}

	return size;
}

void MatchTitleBar(HWND hwnd)
{
	COLORREF color = g_colors.bg;

	if (g_colors.highContrast) {
		return;
	}

	/* Windows 11 보다 앞선 버전은 이 속성을 모르고 실패를 돌려준다. 그대로 둔다. */
	DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &color, sizeof(color));
}

} /* namespace ui */
