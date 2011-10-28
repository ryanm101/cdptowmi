#ifndef __ARGLIST_H_
#define __ARGLIST_H_

#include "versionInfo.h"

// General
#define HELP		'h' // Display Help
#define DEBUG1		'd' // run in debug mode (spew lots to console)
#define MOF			'M' // Generate the MOF file Edits required for SCCM

// CDP info Retrieval
#define ALL			'a' // Dump Everything from CDP to WMI instead of just select data.
#define 


void DisplayHelp() {
	printf(APPNAME"\n");
	printf(COPYRIGHT"\n");
	printf(ABOUT"\n");
}


#endif