#ifndef CHECK_H_
#define CHECK_H_

#define CHECK(x, message) \
 { \
    if(FAILED(x)) {\
        cout << message << ": 0x" << hex << x << endl; \
        CoUninitialize(); \
        return 1; \
    } \
}

#endif // CHECK_H_