#define _WIN32_DCOM

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>

#include "Check.h"
#include "InterfacePtr.h"
#include "MOFScript.h"
using std::cout, std::hex, std::endl;

#pragma comment(lib, "wbemuuid.lib")

int main(int argc, char** argv)
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

    InterfacePtr<IMofCompiler> mofc = nullptr;

    hr = CoCreateInstance(
        CLSID_MofCompiler,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IMofCompiler,
        (LPVOID*)(mofc.GetAddressOf())
    );

    CHECK(hr, "Failed to create compiler object");

    mofc->CompileBuffer(
        MOF_SCRIPT.size(),
        (BYTE*)MOF_SCRIPT.data(),
        BSTR(L"ROOT\\subcription"),
        NULL,
        NULL,
        NULL,
        WBEM_FLAG_CHECK_ONLY,
        0,
        0,
        NULL
    );

    CHECK(hr, "Failed to compile script");
}