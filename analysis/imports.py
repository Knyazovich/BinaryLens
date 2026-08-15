"""Granular sets of Windows APIs used as building blocks by the detection
engine (`binarylens/analysis/indicators/`, `correlation.py`).

None of these sets is, by itself, a verdict. A function appearing in one
of these sets means "this API is relevant to capability/rule X" -- the
correlation engine decides whether the *combination* actually present in
a given binary is worth surfacing as a finding, and at what severity.
"""

from __future__ import annotations

# --- Memory management -----------------------------------------------------

MEMORY_ALLOC_LOCAL_APIS = {
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "VirtualQuery",
    "HeapCreate",
    "HeapAlloc",
    "NtAllocateVirtualMemory",
}

MEMORY_ALLOC_REMOTE_APIS = {
    "VirtualAllocEx",
    "VirtualProtectEx",
    "VirtualFreeEx",
    "VirtualQueryEx",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
}

# --- Process management -----------------------------------------------------

PROCESS_HANDLE_APIS = {
    "OpenProcess",
    "OpenProcessToken",
    "NtOpenProcess",
}

PROCESS_MEMORY_WRITE_APIS = {
    "WriteProcessMemory",
    "NtWriteVirtualMemory",
}

PROCESS_MEMORY_READ_APIS = {
    "ReadProcessMemory",
    "NtReadVirtualMemory",
}

REMOTE_THREAD_APIS = {
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
}

PROCESS_EXECUTION_APIS = {
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteExA",
    "ShellExecuteExW",
    "CreateProcessA",
    "CreateProcessW",
    "CreateProcessAsUserA",
    "CreateProcessAsUserW",
    "CreateProcessWithTokenW",
    "system",
}

# --- Dynamic linking ---------------------------------------------------------

DYNAMIC_RESOLUTION_APIS = {
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "FreeLibrary",
}

# --- File system -------------------------------------------------------------

FILE_SYSTEM_APIS = {
    "CreateFileA",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    "MoveFileExA",
    "MoveFileExW",
    "CopyFileA",
    "CopyFileW",
    "SetFileAttributesA",
    "SetFileAttributesW",
    "FindFirstFileA",
    "FindFirstFileW",
    "GetTempPathA",
    "GetTempPathW",
    "CreateDirectoryA",
    "CreateDirectoryW",
}

# --- Registry -----------------------------------------------------------------

REGISTRY_READ_APIS = {
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegQueryValueExA",
    "RegQueryValueExW",
    "RegEnumKeyExA",
    "RegEnumKeyExW",
}

REGISTRY_WRITE_APIS = {
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegDeleteKeyA",
    "RegDeleteKeyW",
    "RegDeleteValueA",
    "RegDeleteValueW",
}

# --- Service management --------------------------------------------------------

SERVICE_MANAGEMENT_APIS = {
    "OpenSCManagerA",
    "OpenSCManagerW",
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "StartServiceW",
    "ChangeServiceConfigA",
    "ChangeServiceConfigW",
    "ControlService",
    "DeleteService",
    "OpenServiceA",
    "OpenServiceW",
}

# --- Networking -----------------------------------------------------------------

NETWORK_APIS = {
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "InternetReadFile",
    "InternetConnectA",
    "InternetConnectW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpSendRequest",
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
    "bind",
    "listen",
    "accept",
    "gethostbyname",
}

# --- Cryptography -----------------------------------------------------------------

CRYPTOGRAPHY_APIS = {
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptCreateHash",
    "CryptHashData",
    "CryptDeriveKey",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptGenRandom",
    "BCryptOpenAlgorithmProvider",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptGenRandom",
    "CryptProtectData",
    "CryptUnprotectData",
}

# --- Privilege / token management -------------------------------------------------

PRIVILEGE_TOKEN_APIS = {
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueA",
    "LookupPrivilegeValueW",
    "OpenProcessToken",
    "OpenThreadToken",
    "DuplicateTokenEx",
    "ImpersonateLoggedOnUser",
    "SetTokenInformation",
}

# --- Debugging / anti-debugging -----------------------------------------------------

DEBUGGER_DETECTION_APIS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "OutputDebugStringA",
    "OutputDebugStringW",
}

TIMING_APIS = {
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "timeGetTime",
}

# --- GUI -----------------------------------------------------------------------------

GUI_APIS = {
    "MessageBoxA",
    "MessageBoxW",
    "CreateWindowExA",
    "CreateWindowExW",
    "RegisterClassA",
    "RegisterClassW",
    "ShowWindow",
    "UpdateWindow",
    "GetDC",
    "DialogBoxParamA",
    "DialogBoxParamW",
}

# --- System information -------------------------------------------------------------

SYSTEM_INFO_APIS = {
    "GetSystemInfo",
    "GetVersionExA",
    "GetVersionExW",
    "GetComputerNameA",
    "GetComputerNameW",
    "GetUserNameA",
    "GetUserNameW",
    "GetSystemDirectoryA",
    "GetSystemDirectoryW",
    "GetWindowsDirectoryA",
    "GetWindowsDirectoryW",
    "GetVolumeInformationA",
    "GetVolumeInformationW",
    "GetLogicalDrives",
}

# --- Threading / synchronization -----------------------------------------------------

THREADING_APIS = {
    "CreateThread",
    "ExitThread",
    "SuspendThread",
    "ResumeThread",
    "CreateMutexA",
    "CreateMutexW",
    "CreateEventA",
    "CreateEventW",
    "WaitForSingleObject",
    "WaitForMultipleObjects",
    "EnterCriticalSection",
    "LeaveCriticalSection",
}
