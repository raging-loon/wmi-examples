#include <windows.h>
#include <comdef.h>
#include <WbemIdl.h>

#include <iostream>
#include <assert.h>
#pragma comment(lib, "wbemuuid.lib")

using std::cout, std::hex, std::endl;

int main(int argc, char** argv)
{
    HRESULT hr;
    
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);

    if (FAILED(hr))
    {
        cout << "Failed to init COM: 0x" 
             << hex << hr << endl;
        return 1;
    }
    cout << "COM initialized..." << endl;
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
        cout << "Failed to init security: 0x"
             << hex << hr << endl;
        CoUninitialize();
        return 1;
    }

    IWbemLocator* ploc = nullptr;

    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)(&ploc)
    );

    if (FAILED(hr))
    {
        cout << "Failed to create IWbemLocator: 0x"
             << hex << hr << endl;
        CoUninitialize();
        return 1;
    }

    IWbemServices* pSvc = nullptr;

    hr = ploc->ConnectServer(
        _bstr_t(L"ROOT\\subscription"),
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
        cout << "Failed to connect: 0x"
             << hex << hr << endl;
        ploc->Release();
        CoUninitialize();
        return 1;
    }

    cout << "Connected to ROOT\\subscription WMI Namespace" << endl;

    BSTR query = _bstr_t(
         "SELECT * FROM __InstanceCreationEvent "
         "WITHIN 1 WHERE TargetInstance ISA 'Win32_LogonSession'"
    );

    IWbemClassObject* filterClass = nullptr;
    IWbemClassObject* filterInstance = nullptr;
    
    hr = pSvc->GetObject(
        _bstr_t(L"__EventFilter"), 0, NULL, &filterClass, NULL
    );

    if (FAILED(hr))
    {
        cout << "Failed to get __EventFilter object: 0x"
            << hex << hr << endl;
        return 1;
    }

    hr = filterClass->SpawnInstance(0, &filterInstance);

    if (FAILED(hr))
    {
        cout << "Failed to spawn filter instance: 0x"
            << hex << hr << endl;
        return 1;
    }

    VARIANT var;
    var.vt = VT_BSTR;
    var.bstrVal = _bstr_t(L"Test");
    filterInstance->Put(L"Name", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = query;
    filterInstance->Put(L"Query", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = _bstr_t(L"WQL");
    filterInstance->Put(L"QueryLanguage", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = _bstr_t(L"root\\CIMV2");
    filterInstance->Put(L"EventNamespace", 0, &var, 0);
    VariantClear(&var);

    hr = pSvc->PutInstance(filterInstance, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);

    if (FAILED(hr))
    {
        cout << "Failed to set filters: 0x"
            << hex << hr << endl;
        return 1;
    }

    cout << "Set filter..." << endl;

    BSTR consumerName = _bstr_t(L"RunProgramConsumer");
    BSTR cmdLine      = _bstr_t(L"C:\\Program Files\\WindowsDiskMonitor.exe");

    IWbemClassObject* consumerClass;
    IWbemClassObject* consumerInstance;

    hr = pSvc->GetObject(
        _bstr_t("CommandLineEventConsumer"),
        0,
        nullptr,
        &consumerClass,
        nullptr
    );

    if (FAILED(hr))
    {
        cout << "Failed to set consumer class: 0x"
            << hex << hr << endl;
        return 1;
    }
    hr = consumerClass->SpawnInstance(0, &consumerInstance);

    if (FAILED(hr))
    {
        cout << "Failed to spawn consumer instance: 0x"
            << hex << hr << endl;
        return 1;
    }
    var.vt = VT_BSTR;
    var.bstrVal = consumerName;
    consumerInstance->Put(L"Name", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = cmdLine;
    consumerInstance->Put(L"CommandLineTemplate", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BOOL;
    var.boolVal = false;
    consumerInstance->Put(L"RunInteractively", 0, &var, 0);
    VariantClear(&var);


    hr = pSvc->PutInstance(consumerInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);


    if (FAILED(hr))
    {
        cout << "Failed to putInstance: 0x"
            << hex << hr << endl;
        return 1;
    }
    cout << "Set consumer..." << endl;

    IWbemClassObject* pBindingClass = nullptr;
    IWbemClassObject* pBindingInstance = nullptr;

    // Get the __FilterToConsumerBinding class
    hr = pSvc->GetObject(SysAllocString(L"__FilterToConsumerBinding"), 0, nullptr, &pBindingClass, nullptr);
    if (SUCCEEDED(hr)) {
        // Create an instance of __FilterToConsumerBinding
        hr = pBindingClass->SpawnInstance(0, &pBindingInstance);
        if (SUCCEEDED(hr)) {
            VARIANT var;

            // Set the Filter property
            var.vt = VT_BSTR;
            var.bstrVal = SysAllocString(L"\\\\.\\root\\subscription:__EventFilter.Name=\"Test\"");
            pBindingInstance->Put(L"Filter", 0, &var, 0);
            VariantClear(&var);

            // Set the Consumer property
            var.vt = VT_BSTR;
            var.bstrVal = SysAllocString(L"\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\"RunProgramConsumer\"");
            pBindingInstance->Put(L"Consumer", 0, &var, 0);
            VariantClear(&var);

            // Save the binding instance
            hr = pSvc->PutInstance(pBindingInstance, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        }
        else {

                cout << "Failed to get spawn binding instance: 0x"
                    << hex << hr << endl;
                return 1;
        }

    }
    else {
            cout << "Failed to binding class: 0x"
                << hex << hr << endl;
            return 1;
    }

    cout << "Set binding..." << endl;


    if (pSvc)
        pSvc->Release();
    if (ploc)
        ploc->Release();

    CoUninitialize();

    return 0;
}