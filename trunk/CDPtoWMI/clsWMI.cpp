#include "clsWMI.h"

clsWMI::clsWMI() {
	x = 0;
	_debug_ = false;
	clsWMI::ConnectToWMI();
};

clsWMI::clsWMI(wchar_t *clsName) {
	x = 0;
	clsWMI::cname = clsName;
	clsWMI::ConnectToWMI();
}

clsWMI::~clsWMI() {}

void clsWMI::setClassName(wchar_t *clsname) {
	cname = clsname;
}

int clsWMI::ConnectToWMI() {
	HRESULT hres;

    // Initialize COM.
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) {
        if (_debug_) printf("Failed to initialize COM library - %X\n", hres);
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
        pLoc->Release();     
        CoUninitialize();
        return 1;
    }

	if (_debug_) printf("Connected to ROOT\\CIMV2 WMI namespace.\n");
	return 0;
}

void clsWMI::Query() {
	HRESULT hres;
	bstr_t qryLang;
	bstr_t qry;
	qry = "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = True";
	qryLang = "WQL";


	clsWMI::ConnectToWMI();

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
        printf("Failed to create IWbemLocator object. Error code = %X\n", hres);
        CoUninitialize();
        exit(3);       // Program has failed.
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
    
    if (FAILED(hres))
    {
        printf("Could not connect. Error code = %X\n", hres);
        pLoc->Release();     
        CoUninitialize();
        exit(4);                // Program has failed.
    }

    printf("Connected to ROOT\\CIMV2 WMI namespace\n");

    // Set the IWbemServices proxy so that impersonation
    // of the user (client) occurs.
    hres = CoSetProxyBlanket(
       
       pSvc,                         // the proxy to set
       RPC_C_AUTHN_WINNT,            // authentication service
       RPC_C_AUTHZ_NONE,             // authorization service
       NULL,                         // Server principal name
       RPC_C_AUTHN_LEVEL_CALL,       // authentication level
       RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
       NULL,                         // client identity 
       EOAC_NONE                     // proxy capabilities     
    );

    if (FAILED(hres))
    {
        printf("Could not set proxy blanket. Error code = %X\n", hres);
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        exit(5);               // Program has failed.
    }

    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:

    // For example, query for all the running processes
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        qryLang, 
		qry,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);
    
    if (FAILED(hres))
    {
        printf("Query for processes failed. Error code = %X\n", hres);
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        exit(6);               // Program has failed.
    }
    else
    { 
        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;
   
        while (pEnumerator)
        {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, 
                &pclsObj, &uReturn);

            if(0 == uReturn) {
                break;
            }

            VARIANT vtProp;
			char *szText;

            // Get the value of the Name property
            hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
			szText = _com_util::ConvertBSTRToString(vtProp.bstrVal); //convert to char* for display
            printf("Device Name: %s\n",szText);
			VariantClear(&vtProp);

			hres = pclsObj->Get(L"GUID", 0, &vtProp, 0, 0);
			szText = _com_util::ConvertBSTRToString(vtProp.bstrVal);
			printf("Device GUID: %s\n",szText);
            VariantClear(&vtProp);
        }
         
    }
 
    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();     
    CoUninitialize();
}

int clsWMI::DeleteClass() {
	pCtx = 0;
	pResult = 0;

	BSTR Class = SysAllocString(cname);

	HRESULT hres = pSvc->DeleteClass(Class,
		WBEM_FLAG_RETURN_IMMEDIATELY,
		pCtx,
		&pResult);

	return 0;
}

int clsWMI::CreateClass() {
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
	instProperties = new std::string[3];
	dt = cdp->getTS();
	
	for (std::list<clsCDPData>::iterator it = cdp->lstCDPData.begin(); it != cdp->lstCDPData.end(); it++) {
		switch(it->Type) {
			case PLATFORM:
				instProperties[0] = it->To_str();
				break;
			case DEVICEID:
				instProperties[1] = it->To_str();
				break;
			case PORTID:
				instProperties[2] = it->To_str();
				break;
			default:
				break;
		}
	}
	pCreateInstance();
}

int clsWMI::pCreateInstance() {
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

    if (hRes != 0)
       return 1;

    // Create a new instance.
    pClass->SpawnInstance(0, &pNewInstance);
    pClass->Release();  // Don't need the class any more

    VARIANT v;
    VariantInit(&v);

    // Set the Index property (the key).
    V_VT(&v) = VT_I4;
    V_I4(&v) = x;

    BSTR KeyProp = SysAllocString(L"Index");
    pNewInstance->Put(KeyProp, 0, &v, 0);
    SysFreeString(KeyProp);
    VariantClear(&v);
	x++; // Increment Index

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