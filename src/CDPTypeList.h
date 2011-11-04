#ifndef _CDPTYPELIST_H_
#define _CDPTYPELIST_H_

// CDP TypeList
#define DEVICEID			0x0001
#define ADDRESSES			0x0002
#define PORTID				0x0003
#define CAPABILITIES		0x0004
#define SOFTWAREVERSION		0x0005
#define PLATFORM			0x0006

#define	PROTOCOLHELLO		0x0008
#define VTPMGMTDOMAIN		0x0009
#define NATIVEVLAN			0x000a
#define DUPLEX				0x000b


#define VOIPVLANREPLY		0x000e

#define TRUSTBITMAP			0x0012
#define UNTRUSTEDPORTCOS	0x0013


#define MGMTADDRESSES		0x0016

#define POWERAVAILABLE		0x001a

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

#endif
