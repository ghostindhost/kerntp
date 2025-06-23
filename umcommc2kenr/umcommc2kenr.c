#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

#define IOCTL_C2_AUTH   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_C2_QUERY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main()
{
    HANDLE h = CreateFileA("\\\\.\\C2Hybrid", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed to open driver: %u\n", GetLastError());
        return 1;
    }

    // Authenticate and get session token
    UCHAR authIn[32] = "SuperSecret123";
    UCHAR sessionToken[32] = { 0 };
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_C2_AUTH, authIn, sizeof(authIn), sessionToken, sizeof(sessionToken), &ret, NULL);
    if (!ok) {
        printf("Auth failed: %u\n", GetLastError());
        CloseHandle(h);
        return 1;
    }
    printf("Session token acquired!\n");

    // Now send a query
    UCHAR queryBuf[32 + 256] = { 0 };
    UCHAR outBuf[32 + 256] = { 0 };
    memcpy(queryBuf, sessionToken, 32);
    strcpy((char*)queryBuf + 32, "Hello from user DLL!");

    ok = DeviceIoControl(h, IOCTL_C2_QUERY, queryBuf, sizeof(queryBuf), outBuf, sizeof(outBuf), &ret, NULL);
    if (ok) {
        printf("Last C2 command from server: %s\n", outBuf + 32);
    }
    else {
        printf("DeviceIoControl failed: %u\n", GetLastError());
    }

    CloseHandle(h);
    return 0;
}
