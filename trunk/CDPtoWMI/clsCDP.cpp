#include "clsCDP.h"

clsCDP::clsCDP() {}

clsCDP::clsCDP(const u_char** data, int len, std::string dt) {
	printf("IN clsCDP\n\n");
	pktdata = *data;
	capLen = len;
	cimdt = dt;
	CDP_DEBUG();
	printf("\n\nOUT clsCDP\n\n");
}

clsCDP::~clsCDP() {}

void clsCDP::CDP_DEBUG() {
	// Packet processing
	eth_header  *eh;
	llc_header *llch;
	cdp_header *cdph;
    int i=0;

	printf("IN clsCDP::DEBUG()\n\n");
	printf("DateTime (CIM): %s\n\n", cimdt.c_str());
	for (i=1; (i < capLen + 1 ) ; i++) {
			printf("%.2x ", pktdata[i-1]);
			if ( (i % 16) == 0) printf("\n");
	}

	// retrieve the position of the ethernet header
	eh = (eth_header *) (pktdata); //length of ethernet header
	printf("len: %d\n", ntohs(eh->len));
	// retrieve the position of the LLC header
	llch = (llc_header *) (pktdata + 14);
	// retrieve the CDP header
	cdph = (cdp_header *) (pktdata + 22);
	pktdata += 26;

	std::list<clsCDPTriplet> payload;
	int pos = 26;
	while (pos < ntohs(eh->len)) {;
		clsCDPTriplet *cdpt = new clsCDPTriplet(pktdata);
		pos += cdpt->Length - 4;
		payload.push_back(*cdpt);
		cdpt->print();
	}

	printf("OUT clsCDP::DEBUG()\n\n");
}

clsCDPTriplet::clsCDPTriplet(const u_char* &data) {
	u_short *x = (u_short*) data;
	Type = ntohs((u_short) *x);
	Length = ntohs((u_short) *(x+1));

	u_short inc = Length - 4;
	Value = new u_char[Length-3];

	data += 4;

	for (int i=0; (i <= inc ) ; i++) {
			Value[i] = data[i];
	}

	Value[Length-3] = '\0';
	data += inc;
}

clsCDPTriplet::~clsCDPTriplet() {}

void clsCDPTriplet::print() {
	printf("Type   = %.2x\n", Type);
	printf("Length = %d\n", Length);
	printf("Value  = %s\n", Value);
}

