#pragma once

/* 직접 그리는 컨트롤 두 가지. 순수 Win32 다 (MFC 클래스를 파생하지 않는다).
 *
 *   버튼    표준 BUTTON 을 그대로 두고 그리는 것만 맡는다 (BS_OWNERDRAW). 키보드,
 *           포커스, BN_CLICKED 는 원래 컨트롤이 하던 대로다.
 *   탭 줄   새 창 클래스. 공용 컨트롤의 탭은 테두리 있는 상자 모양에서 벗어나지 못한다.
 */

#include <windows.h>

namespace ui {

/* ---- 버튼 ---------------------------------------------------------------- */

enum ButtonKind {
	BUTTON_SECONDARY = 0,	/* 흰 바탕에 테두리 */
	BUTTON_PRIMARY,		/* 강조색. 화면에 하나만 둔다 */
	BUTTON_LINK,		/* 테두리 없이 강조색 글자. 판이 아니라 창 바탕 위에 놓는다.
				 * 자주 쓰지 않는 곳으로 가는 길 */
	BUTTON_CARD_LINK	/* 같은 모양을 판 위에. 판의 한 줄 끝에 붙는 동작 */
};

/* 표준 푸시 버튼을 우리가 그리는 버튼으로 바꾼다. */
void StyleButton(HWND button, ButtonKind kind);
void SetButtonKind(HWND button, ButtonKind kind);

/* 부모의 WM_DRAWITEM 에서 부른다. StyleButton 을 거친 버튼이 아니면 false. */
bool DrawButton(const DRAWITEMSTRUCT *dis);

/* ---- 탭 줄 --------------------------------------------------------------- */

#define UI_TABS_CLASS	L"ZtgateTabs"

/* 탭을 바꾸면 부모에게 WM_COMMAND 를 보낸다 (HIWORD(wParam) == UI_TABS_CHANGED). */
#define UI_TABS_CHANGED	1

/* .rc 가 이 클래스의 컨트롤을 만들 수 있게, 다이얼로그를 띄우기 전에 등록한다. */
bool RegisterTabs(HINSTANCE instance);

void TabsAdd(HWND tabs, LPCWSTR text);
int TabsGetSel(HWND tabs);

/* 탭 글자가 다 들어가는 폭. */
int TabsIdealWidth(HWND tabs);

} /* namespace ui */
