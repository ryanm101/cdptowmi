#ifndef __UTILITY_H_
#define __UTILITY_H_

#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>

inline std::string format_error(std::string str, unsigned __int32 hr) {
  // Code taken from
  // http://social.msdn.microsoft.com/Forums/vstudio/en-US/0016266c-07e4-44b5-a3ec-1a8e106cf57b/convert-hresult-hex-error-code-to-string?forum=vcgeneral
  std::stringstream ss;
  ss << str << std::hex << hr << std::endl;
  return ss.str();
}

inline std::wstring ctow(const char* src) {
    return std::wstring(src, src + strlen(src));
}

inline u_short ctous(const u_char* src, bool net_host) {
	if (net_host) {
		return ntohs(*((u_short *) src));
	} else {
		return *((u_short *) src);
	}
}


inline u_int ctoui(const u_char* src, bool net_host) {
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

inline std::string uctostr(u_char *uc, int uclen) {
	std::string str;
	char *tmp;
	tmp = new char [uclen*2+1];
	for (int i=0;i<uclen;i++) {
		sprintf_s(&tmp[i*2], uclen*2+1, "%02X", *(uc+i));
	}
	str.assign(tmp, uclen*2+1);
	return str;
}

#endif