#include "clsEthFrame.h"

// Constructors & Destructor
clsFRAME::clsFRAME() { }

clsFRAME::clsFRAME(const u_char** data, int len, std::string dt) { 
	pktdata = *data;
	capLen = len;
	cimdt = dt;
}

clsFRAME::~clsFRAME() { }

// Methods
void clsFRAME::setpkt(const u_char** data, int len, std::string dt) { 
	pktdata = *data;
	capLen = len;
	cimdt = dt;
}

int clsFRAME::process() { 
	int result;
	result = processEthHeader();
	if (result != 0) { return result; }
	result = processLLCHeader();
	return result;
}

int clsFRAME::processEthHeader() {
	u_char *tmp = (u_char *) pktdata;
	u_short *tmp2 = (u_short*) (pktdata+12);

	Destination.extractMAC(tmp);
	Source.extractMAC(tmp+6);

	pktlen = ntohs(*tmp2);

	return 0;
}

int clsFRAME::processLLCHeader() {
	u_char *tmp = (u_char *) (pktdata+14);
	u_short *tmp2 = (u_short*) (pktdata+20);
	int x = 0;

	DSAP_IGBit = *(tmp);
	SSAP_CRBit = *(tmp+1);
	ConField   = *(tmp+2);

	for (int i = 3; i<6; i++) {
			OrgCode[x] = *(tmp+i);
			x++;
	}
	OrgCode[3] = '\0';

	PID = ntohs(*tmp2);

	return 0;
}

void clsFRAME::print() {
	printf("\n---- Ethernet Header ----\n");
	printf("Destination:   %s\n", Destination.displayMAC(':').c_str());
	printf("Source:        %s\n", Source.displayMAC(':').c_str());
	printf("Packet Length: %d\n", pktlen);

	printf("\n---- LLC Header ----\n");
	printf("DSAP Address:  0x%02X\n",			LOBYTE(DSAP_IGBit));
	printf("DSAP IG Bit:   0x%02X\n",			HIBYTE(DSAP_IGBit));
	printf("SSAP Address:  0x%02X\n",			LOBYTE(SSAP_CRBit));
	printf("SSAP CR Bit:   0x%02X\n",			HIBYTE(SSAP_CRBit));
	printf("ConField:      0x%02X\n",			ConField);
	printf("OrgCode:       0x%02X%02X%02X\n",	OrgCode[0], OrgCode[1],OrgCode[2]);
	printf("PID:           0x%02X\n",			PID);
}

// Constructors & Destructor
clsCDP::clsCDP(const u_char** data, int len, std::string dt) { 
	pktdata = *data;
	capLen = len;
	cimdt = dt;
}

// Methods
int clsCDP::process() { 
	int result;
	result = processEthHeader();
	if (result != 0) { return result; }
	result = processLLCHeader();
	if (result != 0) { return result; }
	result = processCDPHeader();
	if (result != 0) { return result; }
	result = processCDPPayload();
	return result;
}

int clsCDP::processCDPHeader() { 
	u_char *tmp = (u_char *) (pktdata+22);
	u_short *tmp2 = (u_short*) (pktdata+24);

	version = *tmp;
	ttl = *(tmp+1);
	crc = ntohs(*tmp2);

	return 0;
}

int clsCDP::processCDPPayload() { 
	int pos = 0;
	int numIP = 0;

	while(pos < (pktlen-12)) {
		u_char *tmp = (u_char *) (pktdata+(26+pos));
		u_short *tmp2 = (u_short*) (pktdata+(26+pos));
		clsCDPData *cdpdata = new clsCDPData();

		cdpdata->Type = ntohs(*tmp2);
		cdpdata->Length = ntohs(*(tmp2+(1)));
		cdpdata->Data = new u_char[cdpdata->Length-4];

		for(int i = 0; i < (cdpdata->Length - 3); i++) {
			cdpdata->Data[i] =  *(tmp+4+i);
		}

		lstCDPData.push_back(*cdpdata);	

		if ((cdpdata->Type == ADDRESSES) || (cdpdata->Type == MGMTADDRESSES)) {
			/* length of address data is 17 total for 1 address, 
			/* Type = 2bytes
			/* Length = 2Bytes
			/* Number of IP addresses = 4Bytes
			/* 9 Bytes per IPv4 IP,
			/* Protocol Type = 1Byte
			/* Protocol Len = 1Byte
			/* Protocol = 1Byte
			/* Address Length = 2Bytes
			/* IPv4 Address = 4Bytes
			 */
			numIP = 0;
			clsCDPIP *cdpip = new clsCDPIP();

			numIP = (int) (ntohs(*(tmp2+(2))) + ntohs(*(tmp2+(3)))); // we need 4Bytes but ntohs() only works on 2Bytes at time

			for(int i = 0; i < numIP; i++) {
				cdpip->Type = cdpdata->Type;
				cdpip->ProtoType = *(tmp+(8+i));
				cdpip->ProtoLen = *(tmp+(9+i));
				cdpip->Protocol = *(tmp+(10+i));
				cdpip->AddrLen = (*(tmp+(12+i)) + *(tmp+(11+i))); // As we are dealing with individual bytes just retrieve in correct ordered instead of calling ntohs().

				cdpip->Addr = new u_char[cdpip->AddrLen+1];
				memset(&cdpip->Addr[0], 0, sizeof(cdpip->Addr+1));
				for(int x = 0;x < cdpip->AddrLen; x++) {
					cdpip->Addr[x] = *(tmp+(13+x+i));
				}
				lstCDPIPs.push_back(*cdpip);
			}
		}

		if (cdpdata->Type == PROTOCOLHELLO) {
			int phpos = 4;
			cph = new clsCDPPH();
			// Skip Bytes 0-3 as they are the Type and Length
			cph->OUI = (int) (*(tmp+(phpos)) + *(tmp+(phpos+1)) + *(tmp+(phpos+2))); // we need 3Bytes
			phpos = phpos+3;
			cph->ProtocolID = ctous(tmp+(phpos),true);
			phpos += 2;
			// Cluster Master IP 4Bytes
			phpos += 4;
			cph->unknown0 = ctoui(tmp+(phpos),false);
			phpos += 4;
			cph->version = *(tmp+(phpos++));
			cph->sversion = *(tmp+(phpos++));
			cph->status = *(tmp+(phpos++));
			cph->unknown1 = *(tmp+(phpos++));
            cph->CCMAC.extractMAC((tmp+(phpos))); //Cluster Commander MAC 6Bytes
			phpos += 6;
			cph->SCMAC.extractMAC((tmp+(phpos))); //Switch's MAC 6Bytes
			phpos += 6;
			cph->unknown2 = *(tmp+(phpos++));
			cph->MVLAN = ctous(tmp+(phpos),true);
		}
		pos += (cdpdata->Length);
	}

	return 0;
}

std::string clsCDP::GetProtocol(u_char ID) {
	std::string tmp;
	switch(ID) {
		case PROTO_NULL:
			tmp = "NULL";
			break;
		case PROTO_Q933:
			tmp = "Q.933";
			break;
		case PROTO_IEEESNAP:
			tmp = "IEEE SNAP";
			break;
		case PROTO_ISOCLNP:
			tmp = "ISO CLNP (Connectionless Network Protocol)";
			break;
		case PROTO_ISOESIS:
			tmp = "ISO ES-IS";
			break;
		case PROTO_ISIS:
			tmp = "IS-IS";
			break;
		case PROTO_IPV6:
			tmp = "IPv6";
			break;
		case PROTO_FRF9:
			tmp = "FRF.9";
			break;
		case PROTO_FRF12:
			tmp = "FRF.12";
			break;
		case PROTO_TRILL:
			tmp = "TRILL";
			break;
		case PROTO_IEEE8021AQ:
			tmp = "IEEE 802.1aq";
			break;
		case PROTO_IPV4:
			tmp = "IPv4";
			break;
		case PROTO_PPP:
			tmp = "PPP";
			break;
		default:
			tmp = "Unknown";
			break;
	}
	return tmp;
}

void clsCDP::print() {
	int numIP = 0;
	printf("\n---- Ethernet Header ----\n");
	printf("Destination:   %s\n", Destination.displayMAC(':').c_str());
	printf("Source:        %s\n", Source.displayMAC(':').c_str());
	printf("Packet Length: %d\n", pktlen);

	printf("\n---- LLC Header ----\n");
	printf("DSAP Address:  0x%02X\n",			LOBYTE(DSAP_IGBit));
	printf("DSAP IG Bit:   0x%02X\n",			HIBYTE(DSAP_IGBit));
	printf("SSAP Address:  0x%02X\n",			LOBYTE(SSAP_CRBit));
	printf("SSAP CR Bit:   0x%02X\n",			HIBYTE(SSAP_CRBit));
	printf("ConField:      0x%02X\n",			ConField);
	printf("OrgCode:       0x%02X%02X%02X\n",	OrgCode[0], OrgCode[1],OrgCode[2]);
	printf("PID:           0x%02X\n",			PID);

	printf("\n---- CDP Header ----\n");
	printf("CDP Version:   %d\n",				version);
	printf("CDP ttl:       %d\n",				ttl);
	printf("CDP crc:       0x%02X\n",			crc);

	printf("\n---- CDP Payload ----\n");
	for (std::list<clsCDPData>::iterator it = lstCDPData.begin(); it != lstCDPData.end(); it++) {
		switch(it->Type) {
			case DEVICEID:
				printf("%s:             %s\n",cdptype[DEVICEID].c_str(), it->To_str().c_str());
				break;
			case ADDRESSES:
				numIP = 0; 
				for (std::list<clsCDPIP>::iterator itip = lstCDPIPs.begin(); itip != lstCDPIPs.end(); itip++) {
					if (itip->Type == ADDRESSES) {
						printf("%s%d:           %s\n",cdptype[ADDRESSES].c_str(), numIP,itip->clsIP::getIP().c_str());
						switch(itip->ProtoType) {
							case PROTOT_NLPID:
								printf(" -Protocol Type:        NLPID\n");
								break;
							default:
								printf(" -Protocol Type:             Unknown\n");
								break;
						}
						printf("-Protocol:             %s\n",GetProtocol(itip->Protocol).c_str());
						numIP++;
					}
				}
				break;
			case PORTID:
				printf("%s:          %s\n",cdptype[PORTID].c_str(), it->To_str().c_str());
				break;
			case CAPABILITIES:
				printf("%s:		0x%08X\n",cdptype[CAPABILITIES].c_str(), ctoui(it->Data,true));	
				if (IS_L3R(ctoui(it->Data,true))		!= 0) printf(" -Is a Router\n");
				if (IS_L2TB(ctoui(it->Data,true))		!= 0) printf(" -Is a Transparent Bridge\n");
				if (IS_L2SRB(ctoui(it->Data,true))		!= 0) printf(" -Is a Source Route Bridge\n");
				if (IS_L2SW(ctoui(it->Data,true))		!= 0) printf(" -Is a Switch\n");
				if (IS_L3HOST(ctoui(it->Data,true))		!= 0) printf(" -Is a Host\n");
				if (IS_IGMP(ctoui(it->Data,true))		!= 0) printf(" -Is IGMP capable\n");
				if (IS_L1(ctoui(it->Data,true))			!= 0) printf(" -Is a Repeater\n");
				if (IS_IPPHONE1(ctoui(it->Data,true))	!= 0) printf(" -Is an IPPhone ?? 0x80\n");
				if (IS_IPPHONE2(ctoui(it->Data,true))	!= 0) printf(" -Is an IPPhone ?? 0x0400\n");
				break;
			case SOFTWAREVERSION:
				printf("%s:      %s\n",cdptype[SOFTWAREVERSION].c_str(), it->To_str().c_str());
				break;
			case PLATFORM:
				printf("%s:              %s\n",cdptype[PLATFORM].c_str(), it->To_str().c_str());
				break;
			case PROTOCOLHELLO:
				printf("%s:                  \n",cdptype[PROTOCOLHELLO].c_str());
				printf(" -OUI:				0x%06X\n", cph->OUI);
				if (cph->ProtocolID == PH_PID_CM) {
					printf(" -Protocol ID:			Cluster Management\n");
				} else {
					printf(" -Protocol ID:		0x%04X (Unknown)\n", cph->ProtocolID);
				}
				printf(" -Cluster Master IP:		TODO\n"); // 4Bytes
				printf(" -Unknown (IP?):		0x%08X\n", cph->unknown0);
				printf(" -Version(?):			0x%02X\n", cph->version);
				printf(" -Sub-Version(?):		0x%02X\n", cph->sversion);
				printf(" -Status:			0x%02X\n", cph->status);
				printf(" -Unknown:			0x%02X\n", cph->unknown1);
				printf(" -Cluster Commander MAC:	%s\n", cph->CCMAC.displayMAC(':').c_str()); // 6Bytes
				printf(" -Switches MAC:			%s\n", cph->SCMAC.displayMAC(':').c_str()); // 6Bytes
				printf(" -Unknown:			0x%02X\n", cph->unknown2);
				printf(" -Management VLAN:		%d\n", cph->MVLAN);
				break;
			case VTPMGMTDOMAIN:
				printf("%s: %s\n",cdptype[VTPMGMTDOMAIN].c_str(), it->To_str().c_str());
				break;
			case NATIVEVLAN:
				printf("%s:		%d\n",cdptype[NATIVEVLAN].c_str(), ntohs(*((u_short *) it->Data)));
				break;
			case DUPLEX:
				switch(*it->Data) {
					case DUP_FULL:
						printf("%s:                Full\n",cdptype[DUPLEX].c_str());
						break;
					case DUP_HALF:
						printf("%s:                Half\n",cdptype[DUPLEX].c_str());
						break;
					default:
						printf("%s:                Unknown\n",cdptype[DUPLEX].c_str());
						break;
				}
				break;
			case VOIPVLANREPLY:
				printf("%s:\n",cdptype[VOIPVLANREPLY].c_str());
				if(*it->Data == VOIP_DATA) { // REPLACE WITH SWITCH
					printf ("-Data\n");
				} else {
					printf("-Unknown\n");
				}
				printf("- Voice VLAN:	       %d\n", ctous((it->Data+1),true));
				break;
			case TRUSTBITMAP:
				printf("%s:          %02X\n",cdptype[TRUSTBITMAP].c_str(), *(it->Data));
				break;
			case UNTRUSTEDPORTCOS:
				printf("%s:    %02X\n",cdptype[UNTRUSTEDPORTCOS].c_str(), *(it->Data));
				break;
			case MGMTADDRESSES:
				numIP = 0; 
				for (std::list<clsCDPIP>::iterator itip = lstCDPIPs.begin(); itip != lstCDPIPs.end(); itip++) {
					if (itip->Type == MGMTADDRESSES) {
						printf("%s%d:		%s\n",cdptype[MGMTADDRESSES].c_str(), numIP,itip->clsIP::getIP().c_str());
						if (itip->ProtoType == PROTOT_NLPID) { // REPLACE WITH SWITCH
							printf("-Protocol Type:        NLPID\n");
						} else {
							printf("-Protocol Type:             Unknown\n");
						}
						printf("-Protocol:             %s\n",GetProtocol(itip->Protocol).c_str());
						numIP++;
					}
				}
				break;
			case POWERAVAILABLE:
				printf("%s:       TODO\n",cdptype[POWERAVAILABLE].c_str()/*, it->To_str().c_str()*/);
				break;
			default:
				break;
		}
	}
}

std::string clsCDP::getTS() {
	return cimdt.c_str();
}

// Constructors & Destructor
clsCDPData::clsCDPData() {}

clsCDPData::~clsCDPData() {}

// Methods
std::string clsCDPData::To_str() {
	u_short count = (Length - 4);
	std::string tmp;
	for (int i = 0; i < count; i++) {
		tmp += (char) Data[i];
	}
	return tmp;
}

// Constructors & Destructor
clsCDPPH::clsCDPPH() { }

clsCDPPH::~clsCDPPH() { }

// Constructors & Destructor

clsIP::clsIP() { }

clsIP::clsIP(u_short AddressLength, u_char &Address, u_char Proto) { 
	AddrLen = AddressLength;
	Addr = &Address;
	Protocol = Proto;
}

clsIP::~clsIP() { }

//Methods
std::string clsIP::getIP() {
	std::string tmp;
	if (Protocol == PROTO_IPV4) {
		u_char t;
		char t2[4];
		memset(&t2, 0, 4);
		int x;
		for (int i = 0; i < AddrLen; i++) {
			t = Addr[i];
			x = (int) t;
			_itoa_s(x,t2,sizeof(x),10);
			tmp += t2;
			if (i < (AddrLen -1)) {
				tmp += ".";
			}
		}
	} else {
		tmp = "Unknown - Not IPv4";
	}
	return tmp;
}

// Constructors & Destructor
clsMAC::clsMAC() {}

clsMAC::~clsMAC() {}

//Methods
void clsMAC::setMAC(std::string newMAC) {
	Address = newMAC;
}

std::string clsMAC::getMAC() {
	return Address;
}

std::string clsMAC::displayMAC(const char delim) {
	std::string tmp;
	switch(delim) {
		case ':':
		case '-':
			for (int i = 0; i < 12; i++) {
				tmp += Address[i];
				if ((i % 2 !=0 ) && (i != 11)) {
					tmp += delim;
				}
			}
			break;
		case '.':
			for (int i = 0; i <6; i++) {
				tmp += Address[i];
				if (i == 5) {
					tmp += delim;
				}
			} 
			break;
	}
	return tmp;
}

void clsMAC::extractMAC(u_char *MACOffset) {
	u_char MAC[7];
    for (int i=0; i<6; i++) {
        MAC[i] = *(MACOffset+i);
    }
	MAC[6] = '\0';
	clsMAC::Address = uctostr(MAC, 6);
}

// Constructors & Destructor
clsCDPIP::clsCDPIP() {}

clsCDPIP::~clsCDPIP() {}

//Methods
