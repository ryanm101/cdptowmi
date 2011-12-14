#ifndef _DISPLAYMAPS_H_
#define _DISPLAYMAPS_H_

#include "CDPTypeList.h"
#include <map>
#include <string>

//Define Maps
typedef std::map<unsigned short,std::string> map_us_str;

//Declare Maps
extern map_us_str cdptype;


// Populate
inline void populateMaps() {
// START CDP TYPES
cdptype[DEVICEID]			= "Device ID";
cdptype[ADDRESSES]			= "IP Address";
cdptype[PORTID]				= "Connected to Port";
cdptype[CAPABILITIES]		= "Capabilities";
cdptype[SOFTWAREVERSION]	= "Software Version";
cdptype[PLATFORM]			= "Platform";
cdptype[IPPREFIX]			= "IP Prefix";
cdptype[PROTOCOLHELLO]		= "Protocol Hello";
cdptype[VTPMGMTDOMAIN]		= "VTP Management Domain";
cdptype[NATIVEVLAN]			= "Native VLAN";
cdptype[DUPLEX]				= "Duplex";

cdptype[VOIPVLANREPLY]		= "VOIP VLAN REPLY";
cdptype[VOIPVLANQUERY]		= "VOIP VLAN QUERY";
cdptype[POWER]				= "Power consumption";
cdptype[MTU]				= "MTU";
cdptype[TRUSTBITMAP]		= "Trust Bitmap";
cdptype[UNTRUSTEDPORTCOS]	= "Untrusted port CoS";
cdptype[SYSTEMNAME]			= "System Name";
cdptype[SYSTEMID]			= "System ID";
cdptype[MGMTADDRESSES]		= "Management Address";
cdptype[LOCATION]			= "Location";
cdptype[EXTPORTID]			= "External Port ID";
cdptype[POWERREQUESTED]		= "Power Requested";
cdptype[POWERAVAILABLE]		= "Power Available";
cdptype[PORTUNIDIR]			= "Port Unidirectional";
cdptype[NRGYZ]				= "EnergyWise over CDP";
cdptype[SPAREPOE]			= "Spare Pair PoE";
// END CDP TYPES
}

#endif
