#include "main.h"

using namespace std;
map_us_str cdptype;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
	#ifdef DEBUG
		// if we are debugging lets just redirect straight away
		bool _debug_ = true;
        bool _log_ = true;
		RedirectIOToConsole();
	#else
		bool _debug_ = false;
        bool _log_ = false;
	#endif

	map<string,string> args;
	args["Debug"] = "false";
	args["DryRun"] = "false";
	args["InterfaceName"] = "";
	args["Interface"] = "-1";
	args["offlinefile"] = "";
    args["logfile"] = "";
	processargs(__argc,__argv,_debug_,_log_, args);

	if (strcmp(args["Debug"].c_str(),"true") == 0) _debug_ = true;
    if (strcmp(args["logfile"].c_str(),"") == -1) _log_ = true;

    if (_log_) clslogger::log("*****************************", args["logfile"]);
    if (_log_) clslogger::log("*****************************", args["logfile"]);

	#ifndef DEBUG 
		/* If we are debugging this is already enabled, 
		 * this is for when the debug option is enabled at commandline.
		 */
		if (_debug_) RedirectIOToConsole();
	#endif

    if (_debug_) {
        clslogger::log("MAIN: DryRun = " + args["DryRun"], args["logfile"]);
        clslogger::log("MAIN: InterfaceName = " + args["InterfaceName"], args["logfile"]);
        clslogger::log("MAIN: Interface = " + args["Interface"], args["logfile"]);
        clslogger::log("MAIN: offlinefile = " + args["offlinefile"], args["logfile"]);
    }
	
	populateMaps();
	
	wchar_t *cname = L"NINET_ORG_WMICDP"; // Set the WMI Class Name
    if (_log_) clslogger::log("MAIN: Setting WMI Class Name", args["logfile"]);

	clsWMI *wmi = new clsWMI();
	wmi->_debug_ = _debug_;
    if (_log_) wmi->EnableLogging(args["logfile"]);
	wmi->setClassName(cname);

	if (args["InterfaceName"].length() > 0) {
        if (_log_) clslogger::log("MAIN: Getting NIC: " + args["InterfaceName"], args["logfile"]);
		wmi->getNICs(args["InterfaceName"]);
	} else {
        if (_log_) clslogger::log("MAIN: Getting NICs", args["logfile"]);
		wmi->getNICs();
	}

	if (_debug_) system("Pause");

	clsDump *Dump = new clsDump();
	Dump->_debug_ = _debug_;
	
#ifdef DEBUG
	if (args["offlinefile"].length() > 0) {
		Dump->ReadDump(args["offlinefile"].c_str());
	} else {
#endif
		if(!from_string<int>(Dump->nic_int, args["Interface"], std::hex)) {
			if (_debug_) printf("from_string failed\n");
            if (_log_) clslogger::log("MAIN: from_string failed", args["logfile"]);
			Dump->nic_int = -1;
            if (_log_) clslogger::log("MAIN: nic_int = -1", args["logfile"]);
		}

		Dump->WMI_NICGUID = wmi->getNICGUID();
		if (_debug_) system("Pause");

		Dump->listen();
#ifdef DEBUG
	}
#endif
	if (strcmp(args["DryRun"].c_str(),"true") != 0) {
        if (_log_) clslogger::log("MAIN: Not a Dry run", args["logfile"]);
        if (_log_) clslogger::log("MAIN: Delete WMI Class", args["logfile"]);
		wmi->DeleteClass();
        if (_log_) clslogger::log("MAIN: Create WMI Class", args["logfile"]);
		wmi->CreateClass();

		while(!Dump->lstCDP.empty()) {
            if (_log_) clslogger::log("MAIN: Add Instance", args["logfile"]);
			wmi->CreateInstance(Dump->lstCDP.front());
			Dump->lstCDP.pop_front();
		}
	} else {
		if (_debug_) printf("DryRun: Delete WMI Class\n");
        if (_log_) clslogger::log("MAIN: DryRun, Delete WMI Class", args["logfile"]);
		if (_debug_) printf("DryRun: Create WMI Class - %ls\n", cname);
        if (_log_) clslogger::log("MAIN: DryRun, Create WMI Class", args["logfile"]);
		while(!Dump->lstCDP.empty()) {
            if (_log_) clslogger::log("MAIN: DryRun, Add Instance", args["logfile"]);
			if (_debug_) printf("DryRun: Add Instance\n");
			Dump->lstCDP.pop_front();
		}
		if (_debug_) printf("DryRun: Done\n");
        if (_log_) clslogger::log("MAIN: DryRun, Done", args["logfile"]);
		if (_debug_) system("pause");
	}

	#ifdef DEBUG // For test runs we delete the class as soon as we are finished. 
		system("pause"); 
        if (_log_) clslogger::log("MAIN: DEBUG , Delete Class", args["logfile"]);
        if (_debug_) printf("DEBUG defined: Deleting Class\n");
		wmi->DeleteClass(); 
		system("pause");
	#endif

	return 0;
}
