#ifndef __clsDump_H_
#define __clsDump_H_

#include "clsEthFrame.h"

#include <pcap.h>
#include <WinSock.h>
#include <windows.h>  //needed for waitable timer
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string.h>

#define LINE_LEN 16
#ifdef DEBUG
	/* Set to 99 to loop all interfaces otherwise set to the number 
    *  belonging to the interface that CDP packets are expected on
	*/
	#define DEBUG_NIC 99 
#endif

class clsDump {
	private:
		pcap_if_t *alldevs; //List of all network adapators
		pcap_if_t *conDevs; // Network adaptors with an active connection

	public:
		std::list<clsCDP*> lstCDP;	//List of all CDP Packets captured & processed.

	public:
		clsDump();
		~clsDump();
		void listen();
		

	private:
		int getAdaptors();
		int listener(pcap_if_t *d);
		int ReadDump();
};

#endif
