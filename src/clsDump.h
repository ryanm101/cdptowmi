#ifndef __clsDump_H_
#define __clsDump_H_

#include "clsEthFrame.h"
#include "clslogger.h"

#include <pcap.h>
#include <WinSock.h>
#include <windows.h>  //needed for waitable timer
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string.h>

#define LINE_LEN 16
#define DEBUG_NIC 2 // # of interface to listen on (99 listens on all interfaces)

class clsDump {
	/* Variables */
	private:
		pcap_if_t *alldevs; //List of all network adapators
		pcap_if_t *conDevs; // Network adaptors with an active connection
        bool _log_;
        std::string logfile;

	public:
		std::list<clsCDP*> lstCDP;	//List of all CDP Packets captured & processed.
		std::list<std::string> WMI_NICGUID;
		int nic_int;
		bool _debug_;
		bool use_guid_list;

	/* Methods */
	public:
		clsDump();
		~clsDump();
		void listen();
		void ReadDump(std::string fname);
        void EnableLogging(std::string lf);

	private:
		int getAdaptors();
		int listener(pcap_if_t *d);
};

#endif
