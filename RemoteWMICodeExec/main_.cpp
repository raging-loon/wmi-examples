#define _WIN32_DCOM
#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include "wincred.h"
#include "InterfacePtr.h"
#include "Check.h"

#pragma comment(lib, "wbemuuid.lib")

using std::cout, std::hex, std::endl;


int main(int argc, char** argv)
{
    {
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
        _bstr_t(L"\\\\DESKTOP-HI61N9V\\ROOT\\CIMV2"),
        _bstr_t(L"DESKTOP-HI61N9V\\test"),
        _bstr_t(L"test"),
        NULL,
        NULL,
        NULL, //_bstr_t(L"Kerberos:DESKTOP-HI61N9V"),
        NULL,
        services.GetAddressOf()
    );

    CHECK(hr, "Could not connect");

    cout << "Connected to server" << endl;
    COAUTHIDENTITY userrAcct = {
        .User = (USHORT*)L"test",
        .UserLength = 4,
        .Domain = (USHORT*)(L"DESKTOP-HI61N9V"),
        .DomainLength = 15,
        .Password = (USHORT*)L"test",
        .PasswordLength = 4,
        .Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE
    };
    hr = CoSetProxyBlanket(
        services.Get(),
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &userrAcct,
        EOAC_NONE
    );

    CHECK(hr, "Failed to set proxy blanket");

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
    var.bstrVal = _bstr_t(L"cmd.exe /c echo\"hello\" > C:\\Users\\Test\\Desktop\\Hello.txt");

    inParams->Put(L"CommandLine", 0, &var, 0);

    InterfacePtr<IWbemClassObject> out = nullptr;

    hr = services->ExecMethod(_bstr_t(L"Win32_Process"), _bstr_t(L"Create"), 0, NULL, inParams.Get(), out.GetAddressOf(), NULL);

    CHECK(hr, "Failed to execute method");

    std::wcout << "Send command " << var.bstrVal << endl;

    }

    getchar();
}