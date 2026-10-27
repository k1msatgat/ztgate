#pragma once

#ifndef __AFXWIN_H__
#error "include framework.h before VpnGuiApp.h"
#endif

class CVpnGuiApp : public CWinApp
{
public:
	CVpnGuiApp();

	BOOL InitInstance() override;
	int ExitInstance() override;

private:
	bool m_wsa_ready;
	HANDLE m_instance = nullptr;	/* 창을 하나로 두는 뮤텍스 */
};
