#include "clsWMI.h"

clsWMI::clsWMI() {
	intInstIndex = 0;
	clsWMI::ConnectToWMI();
    logfile = "";
    _log_ = false;
    _debug_ = false;
};

clsWMI::~clsWMI() {
    pSvc->Release();
    pLoc->Release();     
    CoUninitialize();
}

void clsWMI::EnableLogging(std::string lf) {
    logfile = lf;
    _log_ = true;
}

void clsWMI::setClassName(wchar_t *clsname) {
	cname = clsname;
}

int clsWMI::ConnectToWMI() {
	HRESULT hres;

    // Initialize COM.
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) {
        if (_debug_) printf(format_error("Failed to initialize COM library - %X\n", hres).c_str());
        if (_log_) clslogger::log(format_error("clsWMI: ConnectToWMI(), Failed to initialize COM library - ", hres).c_str(),logfile);
        return 1;
    }

    // Initialize 
    hres =  CoInitializeSecurity(
        NULL,     
        -1,							  // COM negotiates service                  
        NULL,						  // Authentication services
        NULL,						  // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
        RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
        NULL,						  // Authentication info 
        EOAC_NONE,					  // Additional capabilities
        NULL						  // Reserved
        );

                      
    if (FAILED(hres)) {
		if (_debug_) printf("Failed to initialize security - %X\n", hres);
        if (_log_) clslogger::log(format_error("clsWMI: ConnectToWMI(), Failed to initialize security - ", hres).c_str(),logfile);
        CoUninitialize();
        return 1;
    }

    pLoc = 0; //initial locator

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres)) {
		if (_debug_) printf("Failed to create IWbemLocator object - %X\n", hres);
        if (_log_) clslogger::log(format_error("clsWMI: ConnectToWMI(), Failed to create IWbemLocator - ", hres).c_str(),logfile);
        CoUninitialize();
        return 1;
    }

	pSvc = 0;

    // Connect to the root\cimv2 namespace with the
    // current user and obtain pointer pSvc
    // to make IWbemServices calls.

    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags                 
        0,                       // Authority       
        0,                       // Context object
        &pSvc                    // IWbemServices proxy
        );                              
    
    if (FAILED(hres)) {
		if (_debug_) printf("Failed to connect - %X\n", hres);
        if (_log_) clslogger::log(format_error("clsWMI: ConnectToWMI(), Failed to connect - ", hres).c_str(),logfile);
        pLoc->Release();     
        CoUninitialize();
        return 1;
    }

	if (_debug_) printf("Connected to ROOT\\CIMV2 WMI namespace.\n");
    if (_log_) clslogger::log("clsWMI: Connected to ROOT\\CIMV2 WMI namespace.",logfile);
	return 0;
}

void clsWMI::getNICs(std::string name) {
	std::string strqry = "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = True AND NetConnectionID like '";
	strqry.append(name);
	strqry.append("'");
    if (_log_) clslogger::log("clsWMI: getNICs(), strqry: "+ strqry ,logfile);
	std::string arrFields[] = {"NetConnectionID","Name","GUID"};
	Query(strqry,arrFields);
}

void clsWMI::getNICs() {
	std::string strqry = "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = True";
    if (_log_) clslogger::log("clsWMI: getNICs(), strqry: "+ strqry ,logfile);
	std::string arrFields[] = {"NetConnectionID","Name","GUID"};
	Query(strqry,arrFields);
}

void clsWMI::Query(std::string strqry, std::string arrProp[]) {
	HRESULT hres;
	bstr_t qryLang;
	bstr_t qry(strqry.c_str());
	qryLang = "WQL";

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        qryLang, 
		qry,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);
    
    if (FAILED(hres)) {
        printf("Query for processes failed. Error code = %X\n", hres);
        if (_log_) clslogger::log(format_error("clsWMI: Query(), Query for processes failed. Error code = ", hres).c_str(),logfile);
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        exit(6);               // Program has failed.
    } else {
		IWbemClassObject *pclsObj;
        ULONG uReturn = 0;
   
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if(0 == uReturn) break; // Exit loop if no results returned from query

            VARIANT vtProp;
			char *szText;
			std::wstring prop;
			std::wstring val;
			map_str qryResult;
            // Get the values of the properties
			int size_of_arrProp = sizeof(arrProp)-1;

			for(int i=0; i<size_of_arrProp; i++) {
				prop = ctow(arrProp[i].c_str());
				hres = pclsObj->Get(prop.c_str(), 0, &vtProp, 0, 0);
				szText = _com_util::ConvertBSTRToString(vtProp.bstrVal); //convert to char*

				if (_debug_) val = ctow(szText);
				if (_debug_) wprintf(L"%s: %s\n",prop.c_str(),val.c_str());

				qryResult[arrProp[i]] = szText;
				VariantClear(&vtProp);
			}
			ResultVec.push_back(qryResult);
        }
	}
}

std::list<std::string> clsWMI::getNICGUID() {
	map_str::iterator mpit;
	std::list<std::string> GUIDList;
	for(std::vector<map_str>::iterator it = ResultVec.begin(); it != ResultVec.end(); ++it) {
		map_str tmp = *it;
		mpit = tmp.find("GUID");
		GUIDList.push_back(mpit->second);
        if (_log_) clslogger::log("clsWMI: getNICGUID(), GUID: " + mpit->second,logfile);
	}
	return GUIDList;
}

int clsWMI::DeleteClass() {
	pCtx = 0;
	pResult = 0;

	BSTR Class = SysAllocString(cname);

	HRESULT hres = pSvc->DeleteClass(Class,
		WBEM_FLAG_RETURN_IMMEDIATELY,
		pCtx,
		&pResult);
    if (_log_) clslogger::log("clsWMI: DeleteClass()",logfile);
	return 0;
}

int clsWMI::CreateClass() {
  if (_log_) clslogger::log("clsWMI: CreateClass()",logfile);
  IWbemClassObject *pNewClass = 0;
  pCtx = 0;
  pResult = 0;

  // Get a class definition. 
  HRESULT hRes = pSvc->GetObject(0, 0, pCtx, &pNewClass, &pResult);
  VARIANT v;
  VariantInit(&v);

  // Create the class name.
  V_VT(&v) = VT_BSTR;
  V_BSTR(&v) = SysAllocString(cname);
  BSTR Class = SysAllocString(L"__CLASS");
  pNewClass->Put(Class, 0, &v, 0);
  SysFreeString(Class);
  VariantClear(&v);

  // Create the key property. 
  BSTR strKeyProp = SysAllocString(L"Index");
  pNewClass->Put(strKeyProp, 0, NULL, CIM_SINT32);

  // Attach Key qualifier to mark the "Index" property as the key.
  IWbemQualifierSet *pQual = 0;
  pNewClass->GetPropertyQualifierSet(strKeyProp, &pQual);
  SysFreeString(strKeyProp);

  V_VT(&v) = VT_BOOL;
  V_BOOL(&v) = VARIANT_TRUE;
  BSTR strKey = SysAllocString(L"Key");

  pQual->Put(strKey, &v, 0);
  SysFreeString(strKey);

  pQual->Release();     
  VariantClear(&v);

  // Create other properties.
  BSTR strProp;

  strProp = SysAllocString(L"TimeStamp");
  pNewClass->Put(strProp, 0, NULL, CIM_DATETIME); // NULL is default
  SysFreeString(strProp);

  strProp = SysAllocString(L"Platform");
  pNewClass->Put(strProp, 0, NULL, CIM_STRING); // NULL is default
  SysFreeString(strProp);

  strProp = SysAllocString(L"DeviceID");
  pNewClass->Put(strProp, 0, NULL, CIM_STRING); // NULL is default
  SysFreeString(strProp);
  
  strProp = SysAllocString(L"PortID");
  pNewClass->Put(strProp, 0, NULL, CIM_STRING); // NULL is default
  SysFreeString(strProp);
  
  // Register the class with WMI
  hRes = pSvc->PutClass(pNewClass, 0, pCtx, &pResult);
  pNewClass->Release();

  return 0;
}

void clsWMI::CreateInstance(clsCDP *cdp) {
    if (_log_) clslogger::log("clsWMI: CreateInstance()",logfile);
	instProperties = new std::string[3];
	dt = cdp->getTS();
	
	for (std::list<clsCDPData>::iterator it = cdp->lstCDPData.begin(); it != cdp->lstCDPData.end(); it++) {
		switch(it->Type) {
			case PLATFORM:
				instProperties[0] = it->To_str();
                if (_log_) clslogger::log("clsWMI: Platform: " + it->To_str(),logfile);
				break;
			case DEVICEID:
				instProperties[1] = it->To_str();
                if (_log_) clslogger::log("clsWMI: DeviceID: " + it->To_str(),logfile);
				break;
			case PORTID:
				instProperties[2] = it->To_str();
                if (_log_) clslogger::log("clsWMI: PortID: " + it->To_str(),logfile);
				break;
			default:
				break;
		}
	}
	pCreateInstance();
}

int clsWMI::pCreateInstance() {
    if (_log_) clslogger::log("clsWMI: pCreateInstance()",logfile);
	pCtx = 0;
	pResult = 0;
    IWbemClassObject *pNewInstance = 0;
    IWbemClassObject *pClass = 0;


    // Get the class definition.
    BSTR PathToClass = SysAllocString(cname);
    HRESULT hRes = pSvc->GetObject(PathToClass, 
									0, 
									pCtx,
									&pClass, 
									&pResult);
    SysFreeString(PathToClass);

    if (hRes != 0) return 1;

    // Create a new instance.
    pClass->SpawnInstance(0, &pNewInstance);
    pClass->Release();  // Don't need the class any more

    VARIANT v;
    VariantInit(&v);

    // Set the Index property (the key).
    V_VT(&v) = VT_I4;
    V_I4(&v) = intInstIndex;

    BSTR KeyProp = SysAllocString(L"Index");
    pNewInstance->Put(KeyProp, 0, &v, 0);
    SysFreeString(KeyProp);
    VariantClear(&v);
	intInstIndex++; // Increment Index

	BSTR strProp;
	
	v.vt=VT_BSTR;
	_bstr_t bstrt(dt.c_str());
	v.bstrVal = bstrt;

	strProp = SysAllocString(L"TimeStamp");
	pNewInstance->Put(strProp, 0, &v, CIM_DATETIME);
	SysFreeString(strProp);

	// use placement new to reuse already allocated memory
	new (&bstrt) _bstr_t(instProperties[0].c_str()); // Assign new string
	v.bstrVal = bstrt;
	
	strProp = SysAllocString(L"Platform");
	pNewInstance->Put(strProp, 0, &v, CIM_STRING);
	SysFreeString(strProp);
	bstrt.~_bstr_t(); // call destructor

	new (&bstrt) _bstr_t(instProperties[1].c_str());
	v.bstrVal = bstrt;

	strProp = SysAllocString(L"DeviceID");
	pNewInstance->Put(strProp, 0, &v, CIM_STRING);
	SysFreeString(strProp);
	bstrt.~_bstr_t();

	new (&bstrt) _bstr_t(instProperties[2].c_str());
	v.bstrVal = bstrt;
  
	strProp = SysAllocString(L"PortID");
	pNewInstance->Put(strProp, 0, &v, CIM_STRING);
	SysFreeString(strProp);
	bstrt.~_bstr_t();
	VariantClear(&v);


    // Write the instance to WMI. 
    hRes = pSvc->PutInstance(pNewInstance, 0, pCtx, &pResult);
    pNewInstance->Release();

	return 0;
}

