#ifndef __clsWMI_H_
#define __clsWMI_H_

#define _WIN32_DCOM

#include "clslogger.h"
#include "clsEthFrame.h"
#include "utility.h"
#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <string>
#include <string.h>
#include <map>
#include <vector>

typedef std::map<std::string,std::string> map_str;

class clsWMI {
	// Variables
	public:
		bool _debug_;
        
	private:
        bool _log_;
        std::string logfile;
		IWbemServices* pSvc;
		IWbemLocator* pLoc;
		IWbemContext* pCtx;
		IWbemCallResult* pResult;
		wchar_t *cname; // WMI Class Name
		int intInstIndex; // Instance Index counter
		std::string *instProperties;
		std::string dt;
		std::vector<map_str> ResultVec;

	// Methods
	public:
		clsWMI();
		~clsWMI();
		
		int DeleteClass();
		int CreateClass();
		void CreateInstance(clsCDP *cdp);
		void setClassName(wchar_t *clsname);
		void getNICs(std::string name);
		void getNICs();
		std::list<std::string> getNICGUID();
        void EnableLogging(std::string lf);

	private:
		void Query(std::string strqry, std::string arrProp[]);
		int pCreateInstance();
		int ConnectToWMI();
};

#endif
