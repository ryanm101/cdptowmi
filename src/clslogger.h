#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <fstream>

class clslogger {
	public:
		clslogger();
		~clslogger();
		static void log(const std::string &str, const std::string logfile);
};

#endif