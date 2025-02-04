#define _WIN32_DCOM

#define _WIN32_DCOM
#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include "wincred.h"
#include "InterfacePtr.h"
#include "Check.h"

#pragma comment(lib, "wbemuuid.lib")

using std::cout, std::wcout, std::hex, std::endl;


int wmain(int argc, wchar_t** argv)
{
    std::wstring domain, username, password, command;

    std::wstring wmiNamespaceName;

    if (argc != 5)
    {
        cout << "Usage: RemoteWMICodeExe [domain] [username] [password] [command]\n";
        return 1;
    }

    domain = argv[1];
    username = domain + L"\\" + argv[2];
    password = argv[3];
    command = argv[4];

    wmiNamespaceName = L"\\\\" + domain + L"\\ROOT\\CIMV2";

        /// Initialize COM
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    
    if (FAILED(hr))
    {
        cout << "Failed to initialize COM: 0x"
            << hex << hr << endl;
        return 1;
    }
    
    /// set up security for the COM interface
    
    cout << "COM Initialized..." << endl;
    
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    
    CHECK(hr, "Failed to initialize security");
    
    InterfacePtr<IWbemLocator> locator = nullptr;
    
    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(locator.GetAddressOf())
    );
    
    
    CHECK(hr, "Failed to create IWbemLocator");
    
    InterfacePtr<IWbemServices> services = nullptr;

    hr = locator->ConnectServer(
        wmiNamespaceName.data(),
        username.data(),
        password.data(),
        NULL,
        NULL,
        NULL,
        NULL,
        services.GetAddressOf()
    );

    CHECK(hr, "Could not connect");

    wcout << L"Connected to " << domain << L" as " << username << endl;

    COAUTHIDENTITY userAcctInfo = {
        .User           = (USHORT*)argv[2],
        .UserLength     = (ULONG)wcslen(argv[2]),
        .Domain         = (USHORT*)domain.data(),
        .DomainLength   = (ULONG)domain.size(),
        .Password       = (USHORT*)password.data(),
        .PasswordLength = (ULONG)password.size(),
        .Flags          = SEC_WINNT_AUTH_IDENTITY_UNICODE
    };

    hr = CoSetProxyBlanket(
        services.Get(),
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &userAcctInfo,
        EOAC_NONE
    );

    CHECK(hr, "Failed to set proxy blanket");

    cout << "Set Proxy Blanket information" << endl;


    InterfacePtr<IWbemClassObject> targetClass = nullptr;
    InterfacePtr<IWbemClassObject> params = nullptr;
    InterfacePtr<IWbemClassObject> inParams = nullptr;

    hr = services->GetObjectW(_bstr_t(L"Win32_Process"), 0, NULL, targetClass.GetAddressOf(), NULL);
    CHECK(hr, "Failed to get object");
   
    hr = targetClass->GetMethod(L"Create", 0, params.GetAddressOf(), NULL);
    CHECK(hr, "Failed to get method");
    
    hr = params->SpawnInstance(0, inParams.GetAddressOf());
    CHECK(hr, "Failed to spawn instance");

    VARIANT var;
    VariantInit(&var);

    var.vt = VT_BSTR;
    var.bstrVal = command.data();
    inParams->Put(L"CommandLine", 0, &var, 0);

    InterfacePtr<IWbemClassObject> out = nullptr;
    hr = services->ExecMethod(_bstr_t(L"Win32_Process"), _bstr_t(L"Create"), 0, NULL, inParams.Get(), out.GetAddressOf(), NULL);

    CHECK(hr, "Failed to execute method");

    wcout << L"Sent command \"" << command << L"\" successfully" << endl;

}
