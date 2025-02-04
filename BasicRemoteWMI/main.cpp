#define _WIN32_DCOM
#define UNICODE

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include <assert.h>
#include <wincred.h>
#include <strsafe.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")

using std::cout, std::hex, std::endl;

int main(int argc, char** argv)
{
    HRESULT hr;

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        cout << "Failed to initialize COM: 0x" << hex << hr << endl;
        return 1;
    }

    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IDENTIFY,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hr))
    {
        cout << "Failed to initialize security: 0x"
            << hex << hr << endl;
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
        cout << "Failed to create Locator object"
             << hex << hr << endl;
        CoUninitialize();
        return 1;
    }

    IWbemServices* pSvc = nullptr;

    CREDUI_INFO cui;
    bool useToken = false;
    bool useNTLM = true;

    wchar_t pszName     [CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
    wchar_t pszPwd      [CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
    wchar_t pszDomain   [CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
    wchar_t pszUserName [CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
    wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };

    BOOL fSave;
    DWORD err;

    memset(&cui, 0, sizeof(CREDUI_INFO));

    cui.cbSize = sizeof(CREDUI_INFO);
    cui.hwndParent = NULL;
    
    cui.pszMessageText = TEXT("Press Cancel to use process token");
    cui.pszCaptionText = TEXT("Enter Account Information");

    cui.hbmBanner = NULL;

    fSave = FALSE;

    err = CredUIPromptForCredentials(
        &cui,
        TEXT("192.168.84.130"),
        NULL,
        0,
        pszName,
        CREDUI_MAX_USERNAME_LENGTH + 1,
        pszPwd,
        CREDUI_MAX_PASSWORD_LENGTH + 1,
        &fSave,
        CREDUI_FLAGS_GENERIC_CREDENTIALS |
        CREDUI_FLAGS_ALWAYS_SHOW_UI |
        CREDUI_FLAGS_DO_NOT_PERSIST
    );

    if (err == ERROR_CANCELLED)
        useToken = true;
    else if (err)
    {
        cout << "Could not get credentials: " << err << endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    if (!useNTLM)
    {
        StringCchPrintf(pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", L"NS1_PAC");
    }

    hr = pLoc->ConnectServer(
        _bstr_t(L"\\\\NS1_PAC\\root\\cimv2"),
        _bstr_t(useToken ? NULL : pszName),
        _bstr_t(useToken ? NULL : pszPwd),
        NULL,
        NULL,
        _bstr_t(useNTLM ? NULL : pszAuthority),
        NULL,
        &pSvc
    );

    if (FAILED(hr))
    {
        cout << "Could not connect to server: 0x" 
             << hex << hr << endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    COAUTHIDENTITY* userAcct = NULL;
    COAUTHIDENTITY authIdent;

    if (!useToken)
    {
        memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
        authIdent.PasswordLength = wcslen(pszPwd);
        authIdent.Password = (USHORT*)pszPwd;

        LPWSTR slash = wcschr(pszName, L'\\');

        if (slash == NULL)
        {
            cout << "Could not create Auth identity. No Domain Specified\n";
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return 1;
        }

        StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
        authIdent.User = (USHORT*)pszUserName;
        authIdent.UserLength = wcslen(pszUserName);

        StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
        authIdent.Domain = (USHORT*)pszDomain;
        authIdent.DomainLength = slash - pszName;
        authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        userAcct = &authIdent;
    }

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        userAcct,
        EOAC_NONE
    );

    if (FAILED(hr))
    {
        cout << "COuld not set proxy blanket: 0x"
             << hex << hr << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    IEnumWbemClassObject* pEnumerator = NULL;

    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr))
    {
        cout << "Query failed: 0x" << hex << hr << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    hr = CoSetProxyBlanket(
        pEnumerator,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        userAcct,
        EOAC_NONE
    );

    if (FAILED(hr))
    {
        cout << "Could not set proxy for enum: 0x" << hex << hr << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    SecureZeroMemory(pszName, sizeof(pszName));
    SecureZeroMemory(pszPwd, sizeof(pszPwd));
    SecureZeroMemory(pszUserName, sizeof(pszUserName));
    SecureZeroMemory(pszDomain, sizeof(pszDomain));

    IWbemClassObject* obj = nullptr;

    ULONG ret = 0;

    while (pEnumerator)
    {
        HRESULT _hr = pEnumerator->Next(WBEM_INFINITE,
            1, &obj, &ret);
        if (ret == 0)
            break;

        VARIANT vtProp;

        VariantInit(&vtProp);

        _hr = obj->Get(L"Name", 0, &vtProp, 0, 0);
        std::wcout << " OS Name: " << vtProp.bstrVal << endl;

        _hr = obj->Get(L"FreePhysicalMemory", 0, &vtProp, 0, 0);

        std::cout << "Free Physical Memory: " << vtProp.uintVal << "kB" << endl;
        VariantClear(&vtProp);

        obj->Release();
        obj = NULL;
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    if (obj)
        obj->Release();

    CoUninitialize();
    return 0;

}