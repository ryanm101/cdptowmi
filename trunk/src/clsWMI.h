#ifndef __clsWMI_H_
#define __clsWMI_H_

#define _WIN32_DCOM

#include "clsEthFrame.h"

#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <string.h>

class clsWMI {
	// Variables
	public:
		bool _debug_;

	private:
		IWbemServices* pSvc;
		IWbemLocator* pLoc;
		IWbemContext* pCtx;
		IWbemCallResult* pResult;
		wchar_t *cname; // WMI Class Name
		int x; // Instance Index counter
		std::string *instProperties;
		std::string dt;

	// Methods
	public:
		clsWMI();
		~clsWMI();
		void Query();
		int DeleteClass();
		int CreateClass();
		void CreateInstance(clsCDP *cdp);
		void setClassName(wchar_t *clsname);

	private:
		int pCreateInstance();
		int ConnectToWMI();
};

#endif
