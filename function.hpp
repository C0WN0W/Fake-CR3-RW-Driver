#pragma once
#include "struct.hpp"
EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb(
    IN PEPROCESS Process
);
EXTERN_C NTSTATUS __declspec(dllexport) DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS FK_ReadMemory(HANDLE pid, ULONG64 baseAddress, ULONG64 buffer, ULONG64 size);
NTSTATUS GetModuleBase(HANDLE ProcessId, LPCSTR ModuleName, PVOID* BaseAddress);

NTSTATUS CallKernelFunction(
    HANDLE ProcessId,
    PVOID EntryPoint,
    PVOID Context
);

NTSTATUS HandleDriverRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp);

EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);