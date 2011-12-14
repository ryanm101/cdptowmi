#ifndef _CDPTYPELIST_H_
#define _CDPTYPELIST_H_

/* CDP Format 
* HEADER
** Version  - 1 Byte
** TTL		- 1 Byte
** Checksum	- 2 Bytes
* DATA
** Type		- 2 Bytes
** Length	- 2 Bytes - Length includes Type,Length AND Value
** Value	- Variable (Value Length = Length - 4)
**************/

// CDP TypeList
#define DEVICEID			0x0001
#define ADDRESSES			0x0002
#define PORTID				0x0003
#define CAPABILITIES		0x0004
#define SOFTWAREVERSION		0x0005
#define PLATFORM			0x0006
#define IPPREFIX			0x0007 // Not seen yet in lab
#define	PROTOCOLHELLO		0x0008
#define VTPMGMTDOMAIN		0x0009
#define NATIVEVLAN			0x000a
#define DUPLEX				0x000b

#define VOIPVLANREPLY		0x000e
#define VOIPVLANQUERY		0x000f // Not seen yet in lab
#define POWER				0x0010 // Not seen yet in lab - Power consumption
#define MTU					0x0011 // Not seen yet in lab
#define TRUSTBITMAP			0x0012
#define UNTRUSTEDPORTCOS	0x0013
#define SYSTEMNAME			0x0014 // Not seen yet in lab
#define SYSTEMID			0x0015 // Not seen yet in lab
#define MGMTADDRESSES		0x0016
#define LOCATION			0x0017 // Not seen yet in lab
#define EXTPORTID			0x0018 // Not seen yet in lab - External Port-ID
#define POWERREQUESTED		0x0019 // Not seen yet in lab - Power Requested
#define POWERAVAILABLE		0x001a
#define PORTUNIDIR			0x001b // Not seen yet in lab - Port Unidirectional
#define NRGYZ				0x001d // Not seen yet in lab - EnergyWise over CDP
#define SPAREPOE			0x001f // Not seen yet in lab - Spare Pair PoE

// Protocol Type List
#define PROTOT_NLPID		0x01

// Protocol List
#define PROTO_NULL			0x00
#define PROTO_Q933			0x08
#define PROTO_IEEESNAP		0x80
#define PROTO_ISOCLNP		0x81
#define PROTO_ISOESIS		0x82
#define PROTO_ISIS			0x83
#define PROTO_IPV6			0x8E
#define PROTO_FRF9			0xB0
#define PROTO_FRF12			0xB1
#define PROTO_TRILL			0xC0
#define PROTO_IEEE8021AQ	0xC1

#define PROTO_IPV4			0xCC

#define PROTO_PPP			0xCF

// Capability masks
#define CAP_L3R				0x01	// layer 3 router
#define CAP_L2TB			0x02	// layer 2 transparent bridge
#define CAP_L2SRB			0x04	// layer 2 source-route bridge
#define CAP_L2SW			0x08	// layer 2 switch (non-spanning tree)
#define CAP_L3HOST			0x10	// layer 3 (non routing) host
#define CAP_IGMP			0x20	// IGMP capable
#define CAP_L1				0x40	// layer 1 repeater
#define CAP_IPPHONEUKNOWN1	0x80	// Uknown but is in a CDP packet from a cisco 8961
#define CAP_IPPHONEUKNOWN2	0x0400	// Uknown but is in a CDP packet from a cisco 8961

//Duplex
#define DUP_FULL			0x01	
#define DUP_HALF			0x00	//Need to verify this

//VOIP VLAN REPLY
#define VOIP_DATA			0x01	//Need to understand this

// Protocol Hello
// - OUI
#define PH_OUI_CISCO		0x00000c

// - ID
#define PH_PID_CM			0x0112	//Cluster Management


// MACROS

// Capability Macros
#define IS_L3R(x)			(x & CAP_L3R)
#define IS_L2TB(x)			(x & CAP_L2TB)
#define IS_L2SRB(x)			(x & CAP_L2SRB)
#define IS_L2SW(x)			(x & CAP_L2SW)
#define IS_L3HOST(x)		(x & CAP_L3HOST)
#define IS_IGMP(x)			(x & CAP_IGMP)
#define IS_L1(x)			(x & CAP_L1)
#define IS_IPPHONE1(x)		(x & CAP_IPPHONEUKNOWN1)
#define IS_IPPHONE2(x)		(x & CAP_IPPHONEUKNOWN2)

#endif
