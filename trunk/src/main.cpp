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
	
	map<string,string> args;
	args["Debug"] = "false";
	args["DryRun"] = "false";
	args["Interface"] = "-1";
	processargs(__argc,__argv,_debug_, args);

	if (strcmp(args["Debug"].c_str(),"true") == 0) _debug_ = true;

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
	if(from_string<int>(Dump->nic_int, args["Interface"], std::hex)) {
		std::cout << Dump->nic_int << std::endl;
	} else {
		std::cout << "from_string failed" << std::endl;
	}
	
	Dump->listen();

	if (strcmp(args["DryRun"].c_str(),"true") != 0) {
		wmi->DeleteClass();
		wmi->CreateClass();

		while(!Dump->lstCDP.empty()) {
			wmi->CreateInstance(Dump->lstCDP.front());
			Dump->lstCDP.pop_front();
		}
	} else {
		if (_debug_) printf("DryRun: Delete WMI Class\n");
		if (_debug_) printf("DryRun: Create WMI Class - %s\n", cname);
		while(!Dump->lstCDP.empty()) {
			if (_debug_) printf("DryRun: Add Instance");
			Dump->lstCDP.pop_front();
		}
		if (_debug_) printf("DryRun: Done");
		if (_debug_) system("pause");
	}

	#ifdef DEBUG // For test runs we delete the class as soon as we are finished. 
		system("pause"); 
		wmi->DeleteClass(); 
		system("pause");
	#endif

	return 0;
}
