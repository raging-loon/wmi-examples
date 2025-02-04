#define _WIN32_DCOM

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include "InterfacePtr.h"
using std::cout, std::hex, std::endl;

#pragma comment(lib, "wbemuuid.lib")

int main(int argc, char** argv)
{
    HRESULT hr;

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);

    if (FAILED(hr))
    {
        cout << "Failed to init COM: 0x" << hex << hr << '\n';
        return 0;
    }
    
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

    if (FAILED(hr))
    {
        cout << "Faield to init security: 0x" << hex << hr << endl;
        CoUninitialize();
        return 1;
    }

    IWbemLocator* pLoc = nullptr;

    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc
    );

    if (FAILED(hr))
    {
        cout << "Failed to create IWbemLocator: 0x" << hex << hr << endl;
        CoUninitialize();
        return 1;
    }

    IWbemServices* pSvc = nullptr;

    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hr))
    {
        cout << "Failed to connect: 0x" << hex << hr << endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    cout << "Connected to ROOT\\CIMV2 WMI Namespace" << endl;

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr))
    {
        cout << "FAield to set proxy: 0x" << hex << hr << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    InterfacePtr<IEnumWbemClassObject> pEnum = nullptr;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        pEnum.GetAddressOf()
    );

    if (FAILED(hr))
    {
        cout << "Failed to submit query: 0x" << hex << hr << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    IWbemClassObject* obj = nullptr;
    ULONG ret = 0;

    while (pEnum.Get())
    {
        HRESULT subHr = pEnum->Next(WBEM_INFINITE, 1, &obj, &ret);
        if (ret == 0)
            break;

        VARIANT vtProp;
        VariantInit(&vtProp);

        subHr = obj->Get(L"Name", 0, &vtProp, 0, 0);
        std::wcout << "OS NAME: " << vtProp.bstrVal << endl;
        VariantClear(&vtProp);

        obj->Release();
    }

    pSvc->Release();
    pLoc->Release();
    pEnum->Release();
    CoUninitialize();
}