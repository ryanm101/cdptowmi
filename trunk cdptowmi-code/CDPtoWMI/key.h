#ifndef __KEY_H_
#define __KEY_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define DSEED 0x4152
#define CSEED 0x5322
#define LSEED 0x4313

bool parseKey(short *key) {
	srand ( time(NULL) );
	bool valid;
	valid = false;
	short year, month, day, clen;
	//Get Exp Year
	year = *(key+4) - DSEED;
	//Get Exp Mon
	month = *(key+6) - DSEED;
	//Get Exp Day
	day = *(key+8) - DSEED;
	//Get Len
	clen = *(key+10) - LSEED;
	//Get CompName

	return valid;
}

#endif