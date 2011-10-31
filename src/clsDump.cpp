#include "clsDump.h"

clsDump::clsDump() {}

clsDump::~clsDump() {}

void clsDump::listen() {
	pcap_if_t *d;
	int i=0;

	if (getAdaptors() == 0 ) {
		for(d= alldevs; d != NULL; d= d->next) { 
			if (_debug_) {
				if (!d->flags & PCAP_IF_LOOPBACK) { // Ignore loopback devices 
					printf("%d. %s", ++i, d->name);
					if (d->description) {
						printf(" (%s)\n\n", d->description);
					} else {
						printf(" (No description available)\n");
					}
				}
			}
			if (_debug_) {
				if ((i == DEBUG_NIC) || (DEBUG_NIC == 99)) {
					listener(d);
				}
			} else {
				listener(d);
			}
		}
		if (i == 0) {
			if (_debug_) printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		}
	}
    pcap_freealldevs(alldevs);
}

int clsDump::getAdaptors() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Get device list from local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        if (_debug_) fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return 1;
    }
	return 0;
}

int clsDump::listener(pcap_if_t *d) {
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ether[12:2] <= 1500 && ether[14:2] == 0xAAAA && ether[16:1] == 0x03 && ether[17:2] == 0x0000 && ether[19:1] == 0x0C && ether[20:2] == 0x2000"; // should be cisco CDP
	struct bpf_program fcode;
	// Packet Handling
	int res;
	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	// Timer
	HANDLE hTimer = NULL;
    LARGE_INTEGER liDueTime;

    liDueTime.QuadPart = -590000000LL;

    // Create an unnamed waitable timer.
    hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (NULL == hTimer)
    {
        if (_debug_) printf("CreateWaitableTimer failed (%d)\n", GetLastError());
        return 1;
    }

	/* Open the device */
    if ( (adhandle= pcap_open(d->name,          // name of the device
                              65536,            // portion of the packet to capture
                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                              PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              ) ) == NULL) {
        if (_debug_) fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

	 /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB) {
        if (_debug_) fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff; 

    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 ) {
        if (_debug_) fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0) {
        if (_debug_) fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
	}

	if (_debug_) printf("Waiting for 59 seconds...\n");

    // Set a timer to wait for 10 seconds.
    if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
    {
        if (_debug_) printf("SetWaitableTimer failed (%d)\n", GetLastError());
        return 2;
    }

    // Wait for the timer.
	
	if (_debug_) printf("\nlistening on %s...\n", d->description);

	/* start the capture */
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0) {

		// Check timer
		if (WaitForSingleObject(hTimer, 0) == WAIT_OBJECT_0) {
			pcap_breakloop(adhandle);
		}
		       
        if(res == 0)
            /* Timeout elapsed */
            continue;
        
        /* convert the timestamp to CIM_DATETIME format */
        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime( timestr, sizeof timestr, "%Y%m%d%H%M%S", &ltime);

		std::string dtstr;
		std::stringstream tmpstream;
		tmpstream << header->ts.tv_usec;
		dtstr = (timestr);
		dtstr.append(".");
		dtstr.append(tmpstream.str());
		dtstr.append("+000");

		clsCDP *cdp;
		cdp = new clsCDP(&pkt_data, header->caplen, dtstr);
		cdp->process();
		if (_debug_) cdp->print();
		lstCDP.push_back(cdp); 
    }

	if (_debug_) {
		if(res == -1){
			printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
			return -1;
		}

		if(res == -2){
			printf("pcap_breakloop() called \n");
			return -2;
		}
	}

	return 0;
}