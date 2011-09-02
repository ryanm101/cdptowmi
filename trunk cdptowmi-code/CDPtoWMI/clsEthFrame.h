#ifndef	__clsEthFrame_H_
#define __clsEthFrame_H_

#include "CDPTypeList.h"
#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <list>

class clsCDPData;

class clsFRAME {
	protected:
		std::string cimdt;		// Timestamp in CIM_DATETIME format

		// Capture
		int capLen;				// Length of capture
		const u_char *pktdata;	// Packet

		// Ethernet Header
		u_char Destination[7]; // 6 Bytes; Destination MAC
		u_char Source[7]; // 6 Bytes; Source MAC
		u_short pktlen; // 2 Bytes; Length of packet (excluding ethernet header)

		// LLC Header
		u_char DSAP_IGBit; //DSAP 4bits, IGBit 4bits
		u_char SSAP_CRBit; //SSAP 4bits, CRBit 4bits
		u_char ConField;  // Control Field 1byte
		u_char OrgCode[4]; // Organisation Code 3bytes
		u_short PID; // PID 2bytes

	public:
		// Constructors & Destructor
		clsFRAME();
		clsFRAME(const u_char** data, int len, std::string dt);
		~clsFRAME();
		// Methods
		void setpkt(const u_char** data, int len, std::string dt);
		int process();
		void print();

	protected:
		int processEthHeader();
		int processLLCHeader();
};

class clsCDP: public clsFRAME {
	public:
		//CDP Header & payload
		u_char version;			// 1 byte   - Version of CDP being used
		u_char ttl;				// 1 byte   - Time to Live
		u_short crc;			// 2 bytes  - Checksum
		std::list<clsCDPData> lstCDPData;  // Variable Data gathered by type

	public:
		// Constructors & Destructor
		clsCDP();
		clsCDP(const u_char** data, int len, std::string dt);
		~clsCDP();
		// Methods
		int process();
		void print();
		std::string getTS();

	private:
		int processCDPHeader();
		int processCDPPayload();
		int processType(u_short datatype, u_short len, u_char *data);
};

class clsCDPData {
	public:
		u_short Type;
		u_short Length;
		u_char *Data;

	public:
		clsCDPData();
		~clsCDPData();
		std::string To_str();
};

#endif