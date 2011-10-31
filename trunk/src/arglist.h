#ifndef __ARGLIST_H_
#define __ARGLIST_H_

#include "versionInfo.h"

// General
#define HELP		'h' // Display Help
#define DEBUG1		'd' // run in debug mode (spew lots to console)
#define MOF			'M' // Generate the MOF file Edits required for SCCM
#define INTERFACE	'i' // Interface to listen on.

// CDP info Retrieval
#define ALL			'a' // Dump Everything from CDP to WMI instead of just select data.

void DisplayHelp() {
	RedirectIOToConsole();
	printf(APPNAME"\n");
	printf(COPYRIGHT"\n");
	printf(ABOUT"\n");
}

#endif