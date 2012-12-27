#ifndef __CDPMAIN_H_
#define __CDPMAIN_H_

#include "displaymaps.h"
#include "clsDump.h"
#include "clsEthFrame.h"
#include "clsWMI.h"
#include "guicon.h"
#include "arglist.h"


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <process.h>
#include <string>
#include <tchar.h>
#include <map>

// Converts STRING to BASE
// from_string(Dest, Source, base)
template <class T>
bool from_string(T& t, const std::string& s, std::ios_base& (*f)(std::ios_base&)) {
  std::istringstream iss(s);
  return !(iss >> f >> t).fail();
}

#endif
