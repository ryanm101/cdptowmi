#ifndef __UTILITY_H_
#define __UTILITY_H_

inline std::wstring ctow(const char* src)
{
    return std::wstring(src, src + strlen(src));
}

#endif