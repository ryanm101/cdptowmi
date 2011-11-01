#ifndef __ARGLIST_H_
#define __ARGLIST_H_

#include "..\resources\versionInfo.h"
#include <map>

// General
#define HELP		'h' // Display Help
#define DEBUG1		'd' // run in debug mode (spew lots to console)
#define NIC_INT		'i' // NIC Interface to listen on.
#define DRYRUN		'w' // Gathers the info but does not touch WMI, should be used with -d

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
	printf(APPNAME"\n");
	printf(COPYRIGHT2"\n");
	printf(ABOUT"\n");
}

void processargs(int cargs, char** vargs, bool _debug_,map<string,string> &arg) {
	if (_debug_) printf("Number of Arguments: %d\n",cargs);
	if (cargs > 1 ) { // Process the arguments
		for(int i=1;i<cargs;i++) {
			if (_debug_) printf("%d: %s\n",i , vargs[i]);
			switch(vargs[i][1]) {
				case HELP:
					DisplayHelp();
					if (_debug_) system("pause");
					exit(0);
				case DEBUG1:
					arg["Debug"] = "true";
					break;
				case DRYRUN:
					arg["DryRun"] = "true";
					break;
				case NIC_INT:
					i++;
					arg["Interface"] = vargs[i];
					break;
				default:
					DisplayHelp();
					if (_debug_) system("pause");
					exit(0);
					break;
			}
		}
	}
}

#endif