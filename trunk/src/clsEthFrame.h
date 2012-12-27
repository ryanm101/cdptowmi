#ifndef	__clsEthFrame_H_
#define __clsEthFrame_H_

#include "CDPTypeList.h"
#include <pcap.h>
#include "displaymaps.h"
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <list>
#include "utility.h"

class clsMAC;
class clsCDPPH;
class clsPowerAvail;
class clsCDPData;
class clsIP;
class clsCDPIP;

class clsMAC {
	public:
		std::string Address;

	public:
		clsMAC();
		~clsMAC();
		void setMAC(std::string newMAC);
		std::string getMAC();
		std::string displayMAC(const char delim);
		void extractMAC(u_char *MACOffset);
	private:

};

class clsFRAME {
	protected:
		std::string cimdt;		// Timestamp in CIM_DATETIME format

		/* Capture */
		int capLen;				// Length of capture
		const u_char *pktdata;	// Packet

		/* Ethernet Header */
		clsMAC Destination;		// 6 Bytes; Destination MAC
		clsMAC Source;			// 6 Bytes; Source MAC
		u_short pktlen;			// 2 Bytes; Length of packet (excluding ethernet header)

		/* LLC Header */
		u_char DSAP;			// DSAP 7bits, IGBit 1bit		
		u_char SSAP;			// SSAP 7bits, CRBit 1bit

		u_char ConField;		// Control Field 1byte
		u_char OrgCode[4];		// Organisation Code 3bytes
		u_short PID;			// PID 2bytes

	public:
		/* Constructors & Destructor */
		clsFRAME();
		clsFRAME(const u_char** data, int len, std::string dt);
		~clsFRAME();
		/* Methods */
		void setpkt(const u_char** data, int len, std::string dt);
		int process();
		void print();

	protected:
		int processEthHeader();
		int processLLCHeader();
};

class clsCDP: public clsFRAME {
	public:
		/* CDP Header & payload */
		u_char version;						// 1 byte   - Version of CDP being used
		u_char ttl;							// 1 byte   - Time to Live
		u_short crc;						// 2 bytes  - Checksum
		u_int IPCount;						// 4 bytes - Number of IPs in Packet
		std::list<clsCDPData> lstCDPData;   // Variable Data gathered by type
		std::list<clsCDPIP> lstCDPIPs;		// Variable IP Data gathered by type
		clsCDPPH *cph;						// Protocol Hello
		clsPowerAvail *pa;					// PowerAvailable

	public:
		/* Constructors & Destructor */
		clsCDP();
		clsCDP(const u_char** data, int len, std::string dt);
		~clsCDP();
		/* Methods */
		int process();
		void print();
		std::string getTS(); // Get Timestamp

	private:
		int processCDPHeader();
		int processCDPPayload();
		int processType(u_short datatype, u_short len, u_char *data);
		std::string GetProtocol(u_char ID);
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

class clsIP {
	public:
		u_short AddrLen;	// 2 bytes
		u_char *Addr;		// 4 bytes
		u_char Protocol;	// 1 byte

	public:
		clsIP();
		clsIP(u_short AddressLength, u_char &Address, u_char Proto);
		~clsIP();
		std::string getIP();
};

class clsCDPIP: public clsIP {
	public:
		u_short Type;		// 2 bytes (management IP, etc.)
		u_char ProtoType;	// 1 byte
		u_char ProtoLen;	// 1 byte
		
	public:
		clsCDPIP();
		clsCDPIP(u_short AddressLength, u_char &Address, u_char Proto);
		~clsCDPIP();
};

/* Protocol Hello */
class clsCDPPH { 
	public:
		u_int	OUI;			//3Bytes
		u_short	ProtocolID;		//2Bytes
		u_int CMIP;				// Cluster Master IP 4Bytes
		u_int unknown0;			//Unknown (IP?) 4 Bytes
		u_char version;			//Version? 1Byte
		u_char sversion;		//Sub-Version? 1Byte
		u_char status;			//Status 1Byte
		u_char unknown1;		//Unknown 1Byte
		clsMAC CCMAC;			//Cluster Commander MAC 6Bytes
		clsMAC SCMAC;			//Switch's MAC 6Bytes
		u_char unknown2;		//Unknown 1Byte
		u_short MVLAN;			//Management Vlan 2Bytes

	public:
		clsCDPPH();
		~clsCDPPH();
};

/* Power Available */
class clsPowerAvail {
	public:
		u_short RequestID;		//2Bytes
		u_short ManagementID;	//2Bytes
		u_long PowerAvail;		//4Bytes
		u_long TotPowerAvail;	//4Bytes

	public:
		clsPowerAvail();
		~clsPowerAvail();
};

#endif
