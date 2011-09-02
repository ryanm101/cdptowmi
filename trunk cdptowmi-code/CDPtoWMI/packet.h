#ifndef __PACKETSTRUCT_H_
#define __PACKETSTRUCT_H_

/* Ethernet Header */
typedef struct eth_header{
	u_char Destination[6]; // Destination MAC
	u_char Source[6]; // Source MAC
	u_short len; // Length of packet (excluding ethernet header)
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
	//u_char type[2];  // 2 bytes  - The Type field indicates the type/length/value type. The possible CDP type/length/value types are as follows:
			         //            Device ID, Address, Port ID, Capabilities, Version, Platform, IP Prefix
	//u_short len;	 // 2 bytes  - Indicates the total length, in bytes, of the type, length, and value fields
	//u_char *val;	 // X Bytes  - The Value field contains the type/length/value value, which depends on the type/length/value type
} cdp_header;

#endif
