#ifndef __UTILITY_H_
#define __UTILITY_H_

#include <string>

inline std::wstring ctow(const char* src)
{
    return std::wstring(src, src + strlen(src));
}

inline u_int ctoui(const u_char* src, bool net_host)
{
	u_int *y = 0;
	u_short a = 0;
	u_short b = 0;
	u_int z = 0;

	y = (u_int *) src; // read 4 Bytes
	if (net_host) {
		a = ntohs(*((u_short *) y)); // Tweak 1st 2 Bytes
		b = ntohs(*((u_short *) y+1)); // Tweak 2nd 2 Bytes
		z = (a + b);
	} else {
		z = *y;
	}
	
    return z;
}

#endif