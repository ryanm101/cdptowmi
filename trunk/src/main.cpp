/**/
#include "main.h"
using namespace std;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
	#ifdef DEBUG
		// if we are debugging lets just redirect straight away
		bool _debug_ = true;
		RedirectIOToConsole();
	#else
		bool _debug_ = false;
	#endif
	
	int argc;
	LPWSTR* szargv;
	szargv = CommandLineToArgvW(GetCommandLineW(), &argc);

	if( NULL == szargv ) {
		if (_debug_) wprintf(L"CommandLineToArgvW failed\n");
		return 1;
	} else {
		for( int i=0; i<argc; i++) {
			if (_debug_) printf("%d: %ws\n", i, szargv[i]);
		}
	}

	#ifndef DEBUG 
		/* If we are debugging this is already enabled, 
		 * this is for when the debug option is enabled at commandline.
		 */
		if (_debug_) RedirectIOToConsole();
	#endif

	wchar_t *cname = L"NINET_ORG_WMICDP"; // Set the WMI Class Name

	clsWMI *wmi = new clsWMI();
	wmi->_debug_ = _debug_;
	wmi->setClassName(cname);

	clsDump *Dump = new clsDump();
	Dump->_debug_ = _debug_;
	Dump->listen();

	wmi->DeleteClass();
	wmi->CreateClass();

	while(!Dump->lstCDP.empty()) {
		wmi->CreateInstance(Dump->lstCDP.front());
		Dump->lstCDP.pop_front();
	}

	#ifdef DEBUG // For test runs we delete the class as soon as we are finished. 
		system("pause"); 
		wmi->DeleteClass(); 
		system("pause");
	#endif

	return 0;
}
