/**/
#include "main.h"
using namespace std;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
	#ifdef DEBUG
		RedirectIOToConsole();
	#endif

	int argc;
	LPWSTR* szargv;
	szargv = CommandLineToArgvW(GetCommandLineW(), &argc);

	if( NULL == szargv ) {
		wprintf(L"CommandLineToArgvW failed\n");
		//return 0;
	} else {
		for( int i=0; i<argc; i++) {
			printf("%d: %ws\n", i, szargv[i]);
		}
	}

	wchar_t *cname = L"NINET_ORG_WMICDP";
	#ifdef DEBUG
		clsWMI *wmi = new clsWMI(true);
	#else
		clsWMI *wmi = new clsWMI(false);
	#endif


	wmi->setClassName(cname);

	clsDump Dump;
	wmi->DeleteClass();
	wmi->CreateClass();

	while(!Dump.lstCDP.empty()) {
		wmi->CreateInstance(Dump.lstCDP.front());
		Dump.lstCDP.pop_front();
	}
#ifdef DEBUG // For test runs we delete the class as soon as we are finished. 
	system("pause"); 
	wmi->DeleteClass(); 
	system("pause");
#endif
	return 0;
}
