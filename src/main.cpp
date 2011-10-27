/**/
#include "main.h"
using namespace std;

int main(int argc, char** argv) {
	wchar_t *cname = L"NINET_ORG_WMICDP";

	if (argc > 1) { // Process Arguments.

	}
	clsWMI *wmi = new clsWMI(cname);

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
