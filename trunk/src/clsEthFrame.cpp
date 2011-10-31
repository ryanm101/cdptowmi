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
	int x = 0;

	for (int i = 0; i<6; i++) {
			Destination[x] = *(tmp+i);
			x++;
	}
	Destination[7] = '\0';

	x = 0;
	for (int i = 6; i<12; i++) {
			Source[x] = *(tmp+i);
			x++;
	}
	Source[6] = '\0';

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
	printf("Destination:   %02X:%02X:%02X:%02X:%02X:%02X\n", 
			Destination[0],	Destination[1],	Destination[2],	Destination[3],
			Destination[4],	Destination[5],	Destination[6]);
	printf("Source:        %02X:%02X:%02X:%02X:%02X:%02X\n",
			Source[0], Source[1], Source[2], Source[3],	Source[4], Source[5], 
			Source[6]);
	printf("Packet Length: %d\n",				pktlen);

	printf("\n---- LLC Header ----\n");
	printf("DSAP Address:  0x%02X\n",			LOBYTE(DSAP_IGBit));
	printf("DSAP IG Bit:   0x%02X\n",			HIBYTE(DSAP_IGBit));
	printf("SSAP Address:  0x%02X\n",			LOBYTE(SSAP_CRBit));
	printf("SSAP CR Bit:   0x%02X\n",			HIBYTE(SSAP_CRBit));
	printf("ConField:      0x%02X\n",			ConField);
	printf("OrgCode:       0x%02X%02X%02X\n",	OrgCode[0], OrgCode[1],OrgCode[2]);
	printf("PID:           0x%02X\n",			PID);
}

clsCDP::clsCDP(const u_char** data, int len, std::string dt) { 
	pktdata = *data;
	capLen = len;
	cimdt = dt;
}

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
		pos += (cdpdata->Length);
	}

	return 0;
}

void clsCDP::print() {
	printf("\n---- Ethernet Header ----\n");
	printf("Destination:   %02X:%02X:%02X:%02X:%02X:%02X\n", 
			Destination[0],	Destination[1],	Destination[2],	Destination[3],
			Destination[4],	Destination[5],	Destination[6]);
	printf("Source:        %02X:%02X:%02X:%02X:%02X:%02X\n",
			Source[0], Source[1], Source[2], Source[3],	Source[4], Source[5], 
			Source[6]);
	printf("Packet Length: %d\n",				pktlen);

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
				printf("Device ID:             %s\n", it->To_str().c_str());
				break;
			case ADDRESSES:
				//printf("XXXXXX:                %s\n", it->To_str().c_str());
				break;
			case PORTID:
				printf("Connected to:          %s\n", it->To_str().c_str());
				break;
			case CAPABILITIES:
				//printf("XXXXX:                 %s\n", it->To_str().c_str());
				break;
			case SOFTWAREVERSION:
				printf("Software Version:      %s\n", it->To_str().c_str());
				break;
			case PLATFORM:
				printf("Platform:              %s\n", it->To_str().c_str());
				break;
			case PROTOCOLHELLO:
				//printf("XXXX:                  %s\n", it->To_str().c_str());
				break;
			case VTPMGMTDOMAIN:
				printf("VTP Management Domain: %s\n", it->To_str().c_str());
				break;
			case NATIVEVLAN:
				//printf("Native VLAN:           %s\n", it->To_str().c_str());
				break;
			case DUPLEX:
				//printf("Duplex:                %s\n", it->To_str().c_str());
				break;
			case VOIPVLANREPLY:
				//printf("VOIP VLAN REPLY:       %s\n", it->To_str().c_str());
				break;
			case TRUSTBITMAP:
				//printf("Trust Bitmap:          %s\n", it->To_str().c_str());
				break;
			case UNTRUSTEDPORTCOS:
				//printf("Untrusted port CoS:    %s\n", it->To_str().c_str());
				break;
			case MGMTADDRESSES:
				//printf("Management Addresses:  %s\n", it->To_str().c_str());
				break;
			case POWERAVAILABLE:
				//printf("Power Available:       %s\n", it->To_str().c_str());
				break;
			default:
				break;
		}
	}
}

std::string clsCDP::getTS() {
	return cimdt.c_str();
}

clsCDPData::clsCDPData() {}

clsCDPData::~clsCDPData() {}

std::string clsCDPData::To_str() {
	u_short count = (Length - 4);
	std::string tmp;
	for (int i = 0; i < count; i++) {
		tmp += (char) Data[i];
	}
	return tmp;
}