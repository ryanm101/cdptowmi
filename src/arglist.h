#ifndef __ARGLIST_H_
#define __ARGLIST_H_

#include "..\resources\versionInfo.h"
#include <map>

// General
#define ARG_HELP		'h' // Display Help
#define ARG_DEBUG		'd' // run in debug mode (spew lots to console)
#define ARG_OFFLINE		'f' // Read packet data from file
#define ARG_NIC_INT		'i' // NIC Interface to listen on.
#define ARG_NIC_NAME	'c' // NIC Name
#define ARG_DRYRUN		'w' // Gathers the info but does not touch WMI, should be used with -d
#define ARG_LOG			'l' // Log to file

/* CDP info Retrieval - Not yet implemented.
#define CDP_ALL			'a' // Dump Everything from CDP to WMI instead of just select data.
#define CDP_			''
#define CDP_			''
#define CDP_			''
#define CDP_			''
#define CDP_			''
*/
void DisplayHelp() {
	RedirectIOToConsole();
	printf("%s\n", APPNAME);
	printf("%s\n\n", COPYRIGHT2);
	printf("%s\n\n", ABOUT);
	printf("%s [-h] [-d] [-f '<filename.pcap>'] [-c '<Connection Name>'] [-i <1>] [-w]\n\n", APPNAME);
	printf("\t-h	\t\tPrints this message\n");
	printf("\t-d	\t\tDebug Mode: All data will be output to screen\n");
	printf("\t-f '<filename.pcap>	Name of PCAP file to use for simulated input,\n\t\t\t\tOnly works with a DEBUG binary\n");
	printf("\t-c '<Connection Name>'	Name of the Network Interface to use for\n\t\t\t\tcapture\n");
	printf("\t-i <i>	\t\tNumber of the interface to use for capture\n");
	printf("\t-w	\t\tProgram will execute and read in CDP Packets\n\t\t\t\tbut will not write to WMI\n\t\t\t\tfor best results use alongside '-d'\n");
	printf("\t-l <filename> \t Log to file.");
}

void processargs(int cargs, char** vargs, bool _debug_, bool _log_, map<string,string> &arg) {
	if (_debug_) printf("Number of Arguments: %d\n",cargs);
	if (cargs > 1 ) { // Process the arguments
		for(int i=1;i<cargs;i++) {
			if (_debug_) printf("%d: %s\n",i , vargs[i]);
			switch(vargs[i][1]) {
				case ARG_HELP:
					DisplayHelp();
					if (_debug_) system("pause");
					exit(0);
				case ARG_DEBUG:
					arg["Debug"] = "true";
					break;
				case ARG_DRYRUN:
					arg["DryRun"] = "true";
					break;
				case ARG_NIC_NAME:
					i++;
					arg["InterfaceName"] = vargs[i];
					break;
				case ARG_NIC_INT:
					i++;
					arg["Interface"] = vargs[i];
					break;
				case ARG_OFFLINE:
					i++;
					arg["offlinefile"] = vargs[i];
					break;
                case ARG_LOG:
                    i++;
                    if (vargs[i] != NULL) {
                        arg["logfile"] = vargs[i];
                    }
                    if ((arg["logfile"] == "") && (_log_)) arg["logfile"] = "c:\\tmp\\cdptowmi.log";
                    break;
				default:
					printf("Unknown paramter '%s'\n", vargs[i]);
					DisplayHelp();
					if (_debug_) system("pause");
					exit(0);
					break;
			}
		}
	}
}

#endif