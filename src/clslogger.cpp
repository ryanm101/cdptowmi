#include "clslogger.h"

clslogger::clslogger() {}
clslogger::~clslogger() {}

void clslogger::log(const std::string &str, const std::string logfile) {
    std::ofstream log_file(logfile, 
		std::ios_base::out | std::ios_base::app );
    log_file << str.c_str() << std::endl;
}