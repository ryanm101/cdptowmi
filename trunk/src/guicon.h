#ifndef __GUICON_H__
#define __GUICON_H__
// Code taken from http://dslweb.nwnexus.com/~ast/dload/guicon.htm

	#include <windows.h>
	#include <stdio.h>
	#include <fcntl.h>
	#include <io.h>
	#include <iostream>
	#include <fstream>

	#ifndef _USE_OLD_IOSTREAMS
		using namespace std;
	#endif

	// maximum mumber of lines the output console should have
	static const WORD MAX_CONSOLE_LINES = 500;
	void RedirectIOToConsole();

#endif
