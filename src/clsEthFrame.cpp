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

	Destination.extractMAC(tmp);
	tmp+=6;
	Source.extractMAC(tmp);
	tmp+=6;
	pktlen = ntohs(*(reinterpret_cast<u_short *> (tmp)));

	return 0;
}

int clsFRAME::processLLCHeader() {
	u_char *tmp = (u_char *) (pktdata+14);

	DSAP = *(tmp++);
	SSAP = *(tmp++);
	ConField = *(tmp++);

	memset(OrgCode,0, sizeof(OrgCode) * 3);
	memcpy(OrgCode,tmp,sizeof(OrgCode) * 3);
	
	PID = ntohs(*(reinterpret_cast<u_short *> (tmp)));

	return 0;
}

void clsFRAME::print() {
	printf("\n---- Ethernet Header ----\n");
	printf("Destination:   %s\n", Destination.displayMAC(':').c_str());
	printf("Source:        %s\n", Source.displayMAC(':').c_str());
	printf("Packet Length: %d\n", pktlen);

	printf("\n---- LLC Header ----\n");
	printf("DSAP Address:  0x%02X\n", DSAP);
	if (IS_DSAP_I(DSAP) == 0) {
		printf("DSAP IG Bit:   Individual (0x00)\n");
	} else {
		printf("DSAP IG Bit:   Group (0x01)\n");
	}
	printf("SSAP Address:  0x%02X\n", SSAP);
	if (IS_SSAP_C(SSAP) == 0) {
		printf("SSAP CR Bit:   Command (0x00)\n");
	} else {
		printf("SSAP CR Bit:   Response (0x01)\n");
	}
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

	version = *tmp++;
	ttl = *(tmp++);
	crc = ntohs(*(reinterpret_cast<unsigned short *> (tmp)));

	return 0;
}

int clsCDP::processCDPPayload() { 
	int pos = 0;
	int numIP = 0;

	while(pos < (pktlen-12)) {
		u_char *tmp = (u_char *) (pktdata+(26+pos));
		u_short *tmp2 = (u_short*) (pktdata+(26+pos));
		clsCDPData *cdpdata = new clsCDPData();

		cdpdata->Type = ntohs(*(reinterpret_cast<unsigned short *> (tmp)));
		tmp+=2;
		cdpdata->Length = ntohs(*(reinterpret_cast<unsigned short *> (tmp)));
		tmp+=2;
		cdpdata->Data = new u_char[cdpdata->Length-3];
		memset(cdpdata->Data,0,cdpdata->Length-3);
		memcpy(cdpdata->Data,tmp,cdpdata->Length-4);

		lstCDPData.push_back(*cdpdata);	

		if ((cdpdata->Type == ADDRESSES) || (cdpdata->Type == MGMTADDRESSES)) {
			/* length of address data is 17 total for 1 address, 
			/* Type = 2bytes
			/* Length = 2Bytes
			/* Number of IP addresses = 4Bytes
			/* 9 Bytes per IPv4 IP,
			/* Protocol Type = 1Byte
			/* Protocol Len = 1Byte
			/* Protocol = 1Byte (Variable)
			/* Address Length = 2Bytes
			/* IPv4 Address = 4Bytes
			 */
			numIP = 0;
			//numIP = ( ntohs(*(reinterpret_cast<unsigned short *> (tmp))) + ntohs(*(reinterpret_cast<unsigned short *> (tmp+1))) );
			numIP = (int) (ntohs(*(tmp2+(2))) + ntohs(*(tmp2+(3)))); // we need 4Bytes but ntohs() only works on 2Bytes at time
			tmp+=4; // Move to start of IP Address
			for(int i = 0; i < numIP; i++) {
				clsCDPIP *cdpip = new clsCDPIP();
				cdpip->Type = cdpdata->Type;
				cdpip->ProtoType = *(tmp++);
				cdpip->ProtoLen = *(tmp++);  // FIXME - will not handle protocol lengths > 1
				cdpip->Protocol = *(tmp++);
				cdpip->AddrLen = (*(tmp+1)) + *(tmp); // As we are dealing with individual bytes just retrieve in correct ordered instead of calling ntohs().
				tmp+=2; // Move along two places
				cdpip->Addr = new u_char[cdpip->AddrLen+1];
				memset(cdpip->Addr, 0, cdpip->AddrLen+1);
				memcpy(cdpip->Addr,tmp,cdpip->AddrLen);
				lstCDPIPs.push_back(*cdpip);
			}
		}

		if (cdpdata->Type == PROTOCOLHELLO) {
			cph = new clsCDPPH();
			cph->OUI = (int) (*(tmp) + *(tmp+1) + *(tmp+2)); // we need 3Bytes
			tmp+=3;
			cph->ProtocolID = ctous(tmp,true);
			tmp+=2;
			cph->CMIP = ctoui(tmp,false); // Cluster Master IP 4Bytes
			tmp+=4;
			cph->unknown0 = ctoui(tmp,false);
			tmp+=4;
			cph->version = *(tmp++);
			cph->sversion = *(tmp++);
			cph->status = *(tmp++);
			cph->unknown1 = *(tmp++);
            cph->CCMAC.extractMAC((tmp)); //Cluster Commander MAC 6Bytes
			tmp+=6;
			cph->SCMAC.extractMAC((tmp)); //Switch's MAC 6Bytes
			tmp+=6;
			cph->unknown2 = *(tmp++);
			cph->MVLAN = ctous(tmp,true);
		}

		if (cdpdata->Type == POWERAVAILABLE) {
			int papos = 2;
			pa = new clsPowerAvail();
			pa->RequestID = ntohs(*(reinterpret_cast<unsigned short *> (tmp)));
			tmp+=2;
			pa->ManagementID = ntohs(*(reinterpret_cast<unsigned short *> (tmp)));
			tmp+=2;
			memcpy(&pa->PowerAvail, tmp, 4);
			tmp+=4;
			memcpy(&pa->TotPowerAvail, tmp, 4);
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
	printf("DSAP Address:  0x%02X\n", DSAP);
	if (IS_DSAP_I(DSAP) == 0) {
		printf("DSAP IG Bit:   Individual (0x00)\n");
	} else {
		printf("DSAP IG Bit:   Group (0x01)\n");
	}
	printf("SSAP Address:  0x%02X\n", SSAP);
	if (IS_SSAP_C(SSAP) == 0) {
		printf("SSAP CR Bit:   Command (0x00)\n");
	} else {
		printf("SSAP CR Bit:   Response (0x01)\n");
	}
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
				printf("%s:             \t\t%s\n",cdptype[DEVICEID].c_str(), it->To_str().c_str());
				break;
			case ADDRESSES:
				printf("Addressses:\n");
				numIP = 0; 
				for (std::list<clsCDPIP>::iterator itip = lstCDPIPs.begin(); itip != lstCDPIPs.end(); itip++) {
					if (itip->Type == ADDRESSES) {
						printf(" -%s%d:           \t%s\n",cdptype[ADDRESSES].c_str(), numIP,itip->clsIP::getIP().c_str());
						switch(itip->ProtoType) {
							case PROTOT_NLPID:
								printf(" --Protocol Type:        \tNLPID (0x%02X)\n",itip->ProtoType);
								break;
							default:
								printf(" --Protocol Type:             \tUnknown (0x%02X)\n",itip->ProtoType);
								break;
						}
						printf(" --Protocol:             \t%s\n",GetProtocol(itip->Protocol).c_str());
						numIP++;
					}
				}
				break;
			case PORTID:
				printf("%s:          \t%s\n",cdptype[PORTID].c_str(), it->To_str().c_str());
				break;
			case CAPABILITIES:
				printf("%s:		\t0x%08X\n",cdptype[CAPABILITIES].c_str(), ctoui(it->Data,true));	
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
				printf("%s:      \t\t%s\n",cdptype[SOFTWAREVERSION].c_str(), it->To_str().c_str());
				break;
			case PLATFORM:
				printf("%s:              \t\t%s\n",cdptype[PLATFORM].c_str(), it->To_str().c_str());
				break;
			case PROTOCOLHELLO:
				printf("%s:                  \n",cdptype[PROTOCOLHELLO].c_str());
				printf(" -OUI:				0x%06X\n", cph->OUI);
				if (cph->ProtocolID == PH_PID_CM) {
					printf(" -Protocol ID:			Cluster Management\n");
				} else {
					printf(" -Protocol ID:		0x%04X (Unknown)\n", cph->ProtocolID);
				}
				printf(" -Cluster Master IP:		0x%08X\n", cph->CMIP);
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
				printf("%s:	\t%s\n",cdptype[VTPMGMTDOMAIN].c_str(), it->To_str().c_str());
				break;
			case NATIVEVLAN:
				printf("%s:	\t\t%d\n",cdptype[NATIVEVLAN].c_str(), ntohs(*((u_short *) it->Data)));
				break;
			case DUPLEX:
				switch(*it->Data) {
					case DUP_FULL:
						printf("%s:                \t\tFull\n",cdptype[DUPLEX].c_str());
						break;
					case DUP_HALF:
						printf("%s:                \t\tHalf\n",cdptype[DUPLEX].c_str());
						break;
					default:
						printf("%s:                \t\tUnknown\n",cdptype[DUPLEX].c_str());
						break;
				}
				break;
			case VOIPVLANREPLY:
				printf("%s:\n",cdptype[VOIPVLANREPLY].c_str());
				switch(*it->Data) {
					case VOIP_DATA:
						printf (" -Data\n");
						break;
					default:
						printf(" -Unknown\n");
						break;
				}
				printf("--Voice VLAN:	       \t%d\n", ctous((it->Data+1),true));
				break;
			case TRUSTBITMAP:
				printf("%s:          \t\t%02X\n",cdptype[TRUSTBITMAP].c_str(), *(it->Data));
				break;
			case UNTRUSTEDPORTCOS:
				printf("%s:    \t\t%02X\n",cdptype[UNTRUSTEDPORTCOS].c_str(), *(it->Data));
				break;
			case MGMTADDRESSES:
				printf("Management Addressses:\n");
				numIP = 0; 
				for (std::list<clsCDPIP>::iterator itip = lstCDPIPs.begin(); itip != lstCDPIPs.end(); itip++) {
					if (itip->Type == MGMTADDRESSES) {
						printf(" -%s%d:		%s\n",cdptype[MGMTADDRESSES].c_str(), numIP,itip->clsIP::getIP().c_str());
						switch(itip->ProtoType) {
							case PROTOT_NLPID:
								printf(" --Protocol Type:        \tNLPID\n");
								break;
							default:
								printf(" --Protocol Type:             \tUnknown\n");
								break;
						}
						printf(" --Protocol:             \t%s\n",GetProtocol(itip->Protocol).c_str());
						numIP++;
					}
				}
				break;
			case POWERAVAILABLE:
				printf("%s:\n",cdptype[POWERAVAILABLE].c_str());
				printf(" -Request-ID: \t\t\t%i\n",pa->RequestID);
				printf(" -Management-ID: \t\t%i\n",pa->ManagementID);
				printf(" -Power Available: \t\t%u\n",pa->PowerAvail);
				printf(" -Total Power Available: \t%u\n",pa->TotPowerAvail);
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

clsCDPIP::clsCDPIP(u_short AddressLength, u_char &Address, u_char Proto) {}

clsCDPIP::~clsCDPIP() {}

//Methods



// Constructors & Destructor
clsPowerAvail::clsPowerAvail() {}

clsPowerAvail::~clsPowerAvail() {}

//Methods