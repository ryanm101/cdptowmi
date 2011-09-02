#ifndef	__clsCDP_H_
#define __clsCDP_H_

#include "CDPTypeList.h"
#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <list>

/* Ethernet Header */
typedef struct eth_header{
	u_char Destination[6]; // 6 Bytes; Destination MAC
	u_char Source[6]; // 6 Bytes; Source MAC
	u_short len; // 2 Bytes; Length of packet (excluding ethernet header)
}eth_header;

typedef struct llc_header{
	u_char DSAP_IGBit; //DSAP 4bits, IGBit 4bits
	u_char SSAP_CRBit; //SSAP 4bits, CRBit 4bits
	u_char ConField;  // Control Field 1byte
	u_char OrgCode[3]; // Organisation Code 3bytes
	u_short PID; // PID 2bytes
}llc_header;

/* CDP */
typedef struct cdp_header{
	u_char version;  // 1 byte   - Version of CDP being used
	u_char ttl;	     // 1 byte   - Time to Live
	u_short crc;	 // 2 bytes  - Checksum
} cdp_header;

class clsCDP {
	private:
		u_char version;			// 1 byte   - Version of CDP being used
		u_char ttl;				// 1 byte   - Time to Live
		u_short crc;			// 2 bytes  - Checksum
		int capLen;				// Length of capture
		std::string cimdt;		// Timestamp in CIM_DATETIME format
		const u_char *pktdata;	// Packet

	public:
		clsCDP();
		clsCDP(const u_char** data, int len, std::string dt);
		~clsCDP();
		void CDP_DEBUG();

	private:
};

class clsCDPTriplet {
	public:
		u_short Type;		//2 bytes  - The Type field indicates the type/length/value type. The possible CDP type/length/value types are as follows:
							//			 Device ID, Address, Port ID, Capabilities, Version, Platform, IP Prefix, etc.
		u_short	Length;		//2 bytes  - Indicates the total length, in bytes, of the type, length, and value fields
		u_char	*Value;		//X Bytes  - The Value field contains the data.

	public:
		clsCDPTriplet(const u_char* &data);
		~clsCDPTriplet();
		void print();

	private:

};

#endif
