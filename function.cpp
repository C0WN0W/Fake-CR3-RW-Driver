#include "function.hpp"

NTSTATUS FindProcessByName(LPCWSTR processName, PEPROCESS& process) {
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, 'proc');
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (processInfo) {
        if (processInfo->ImageName.Buffer && wcscmp(processName, processInfo->ImageName.Buffer) == 0) {

            status = PsLookupProcessByProcessId((HANDLE)processInfo->UniqueProcessId, &process);
            if (NT_SUCCESS(status)) {
                break;
            }
        }

        if (!processInfo->NextEntryOffset) {
            break;
        }
        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, 'proc');
    return status;
}

static PEPROCESS fakeProcess = nullptr;

NTSTATUS InitFakeProcess(HANDLE pid)
{
    // DbgBreakPoint();
    static PEPROCESS winlogProcess = NULL;

    PEPROCESS Process = NULL;
    PVOID BaseAddress = NULL;

    NTSTATUS st = PsLookupProcessByProcessId(pid, &Process);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    // check if the process is valid
    if (PsGetProcessExitStatus(Process) != STATUS_PENDING) {
        ObDereferenceObject(Process);  // release the reference to the process object
        return STATUS_UNSUCCESSFUL;
    }


    if (!winlogProcess) {
        FindProcessByName(L"winlogon.exe", winlogProcess);
    }
    if (!winlogProcess) {
        ObDereferenceObject(Process);
        return STATUS_UNSUCCESSFUL;
    }

    static char Object[PAGE_SIZE];
    memset(Object, 0, PAGE_SIZE);

    KAPC_STATE kapcState = { 0 };
    KeStackAttachProcess(winlogProcess, &kapcState);
    memcpy(Object, (PUCHAR)winlogProcess - 0x30, 0xef0); //head+eprocesss


    fakeProcess = (PEPROCESS)((PUCHAR)Object + 0x30);
    KeUnstackDetachProcess(&kapcState);


    //ULONG64 gameCr3 = *(PULONG64)((ULONG64)Process + 0x28);//游戏的cr3

    KeStackAttachProcess(Process, &kapcState);
    ULONG cr3 = *(PULONG)((PUCHAR)Process + 0x28);
    KeUnstackDetachProcess(&kapcState);

    ULONG msize = PAGE_SIZE;
    HANDLE hMemory = NULL;
    UNICODE_STRING unName = { 0 };
    RtlInitUnicodeString(&unName, L"\\Device\\PhysicalMemory");
    // initialize the object attributes
    OBJECT_ATTRIBUTES obj;
    InitializeObjectAttributes(&obj, &unName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS status = ZwOpenSection(&hMemory, SECTION_ALL_ACCESS, &obj);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(77, 0, "Failed to open physical memory section: 0x%lx\n", status);
        return status;
    }
    PVOID mem = NULL;// use this to map the physical memory
    SIZE_T sizeView = PAGE_SIZE; // the size of the view
    LARGE_INTEGER lage = { 0 };
    lage.QuadPart = cr3;// the offset of the physical memory to be mapped

    PVOID sectionObj = NULL;
    status = ObReferenceObjectByHandle(hMemory, SECTION_ALL_ACCESS, NULL, KernelMode, &sectionObj, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(77, 0, "Failed to reference section object: 0x%lx\n", status);
        ZwClose(hMemory);
        return status;
    }
    // mapping the section
    status = ZwMapViewOfSection(hMemory,
        NtCurrentProcess(), &mem,
        0, msize, &lage, &sizeView, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(77, 0, "Failed to map view of section: 0x%lx\n", status);
        ObDereferenceObject(sectionObj);
        ZwClose(hMemory);
        return status;
    }
    //Copy CR3	
    static char srcCr3[PAGE_SIZE];
    memset(srcCr3, 0, PAGE_SIZE);
    memcpy(srcCr3, mem, msize);
    PHYSICAL_ADDRESS srcphyCr3 = MmGetPhysicalAddress(srcCr3);
    //*(PULONG64)((ULONG64)fakeProcess + 0x28) = gameCr3;
    *(PULONG64)((ULONG64)fakeProcess + 0x28) = srcphyCr3.LowPart;

    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

NTSTATUS FK_ReadMemory(PVOID baseAddress, PVOID buffer, ULONG64 size) {
    if (!fakeProcess)
    {
        return STATUS_UNSUCCESSFUL;
    }
    SIZE_T retSize = 0;
    return MmCopyVirtualMemory(fakeProcess, baseAddress, IoGetCurrentProcess(), buffer, size, UserMode, &retSize);
}

NTSTATUS GetModuleBase(HANDLE ProcessId, LPCSTR ModuleName, PVOID* BaseAddress)
{
    if (!ModuleName || !BaseAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    *BaseAddress = NULL;

    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    __try {
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);

        __try {
            PPEB Peb = PsGetProcessPeb(Process);
            if (!Peb) {
                Status = STATUS_UNSUCCESSFUL;
                __leave;
            }

            if (_stricmp(ModuleName, "") == 0 || _stricmp(ModuleName, "exe") == 0) {
                *BaseAddress = Peb->ImageBaseAddress;
                Status = *BaseAddress ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                __leave;
            }

            if (!Peb->Ldr) {
                Status = STATUS_UNSUCCESSFUL;
                __leave;
            }

            PPEB_LDR_DATA Ldr = Peb->Ldr;
            PLIST_ENTRY ModuleList = &Ldr->InLoadOrderModuleList;
            PLIST_ENTRY Entry = ModuleList->Flink;

            while (Entry && Entry != ModuleList) {
                PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (!Module || !Module->BaseDllName.Buffer) {
                    Entry = Entry->Flink;
                    continue;
                }

                char ModuleNameBuffer[256] = { 0 };
                ULONG ConvertedLength = 0;

                Status = RtlUnicodeToMultiByteN(
                    ModuleNameBuffer,
                    sizeof(ModuleNameBuffer) - 1,
                    &ConvertedLength,
                    Module->BaseDllName.Buffer,
                    Module->BaseDllName.Length
                );

                if (NT_SUCCESS(Status)) {
                    ModuleNameBuffer[ConvertedLength] = '\0';

                    if (_stricmp(ModuleNameBuffer, ModuleName) == 0) {
                        *BaseAddress = Module->DllBase;
                        Status = STATUS_SUCCESS;
                        __leave;
                    }
                }

                Entry = Entry->Flink;
            }
            Status = STATUS_NOT_FOUND;
        }
        __finally {
            KeUnstackDetachProcess(&ApcState);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS CallKernelFunction(HANDLE ProcessId, PVOID EntryPoint, PVOID Context)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    HANDLE ThreadHandle;
    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)EntryPoint,
        Context
    );

    if (NT_SUCCESS(Status)) {
        ZwClose(ThreadHandle);
    }

    ObDereferenceObject(Process);
    return Status;
}

auto getprocessdirbase(PEPROCESS targetprocess) -> ULONG_PTR
{
    if (!targetprocess)
        return 0;

    PUCHAR process = (PUCHAR)targetprocess;
    ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
    return process_dirbase;
}

auto readphysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
{
    if (!address)
        return STATUS_UNSUCCESSFUL;

    MM_COPY_ADDRESS addr = { 0 };
    addr.PhysicalAddress.QuadPart = (LONGLONG)address;
    return MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, read);
}
#define PAGE_OFFSET_SIZE 12
constexpr uint64_t mask = (~0xfull << 8) & 0xfffffffffull;

auto translateaddress(uint64_t processdirbase, uint64_t address) -> uint64_t
{
    processdirbase &= ~0xf;

    uint64_t pageoffset = address & ~(~0ul << PAGE_OFFSET_SIZE);
    uint64_t pte = ((address >> 12) & (0x1ffll));
    uint64_t pt = ((address >> 21) & (0x1ffll));
    uint64_t pd = ((address >> 30) & (0x1ffll));
    uint64_t pdp = ((address >> 39) & (0x1ffll));

    SIZE_T readsize = 0;
    uint64_t pdpe = 0;
    readphysaddress((void*)(processdirbase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
    if (~pdpe & 1)
        return 0;

    uint64_t pde = 0;
    readphysaddress((void*)((pdpe & mask) + 8 * pd), &pde, sizeof(pde), &readsize);
    if (~pde & 1)
        return 0;

    if (pde & 0x80)
        return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

    uint64_t ptraddr = 0;
    readphysaddress((void*)((pde & mask) + 8 * pt), &ptraddr, sizeof(ptraddr), &readsize);
    if (~ptraddr & 1)
        return 0;

    if (ptraddr & 0x80)
        return (ptraddr & mask) + (address & ~(~0ull << 21));

    address = 0;
    readphysaddress((void*)((ptraddr & mask) + 8 * pte), &address, sizeof(address), &readsize);
    address &= mask;

    if (!address)
        return 0;

    return address + pageoffset;
}

auto readprocessmemory(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
{
    // DbgBreakPoint();
    auto process_dirbase = getprocessdirbase(fakeProcess);

    SIZE_T curoffset = 0;
    while (size)
    {
        auto addr = translateaddress(process_dirbase, (ULONG64)address + curoffset);
        if (!addr) return STATUS_UNSUCCESSFUL;

        ULONG64 readsize = min(PAGE_SIZE - (addr & 0xFFF), size);
        SIZE_T readreturn = 0;
        auto readstatus = readphysaddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), readsize, &readreturn);
        size -= readreturn;
        curoffset += readreturn;
        if (readstatus != STATUS_SUCCESS) break;
        if (readreturn == 0) break;
    }

    *read = curoffset;
    return STATUS_SUCCESS;
}

NTSTATUS HandleDriverRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID InputBuffer = NULL;
    PVOID OutputBuffer = NULL;
    ULONG InputBufferLength = 0;
    ULONG OutputBufferLength = 0;

    switch (Stack->MajorFunction)
    {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;

    case IRP_MJ_DEVICE_CONTROL:
    {
        InputBuffer = Irp->AssociatedIrp.SystemBuffer;
        OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
        InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        OutputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!InputBuffer || !OutputBuffer || !InputBufferLength || !OutputBufferLength)
        {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
        }

        prequest_data Request = (prequest_data)InputBuffer;
        if (!Request)
        {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
        }

        switch (Request->code)
        {
        case init_driver:
        {
            pdriver_init Init = (pdriver_init)Request->data;
            if (!Init)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Init->init = true;
            Irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        }
        case get_base:
        {
            pbase_request Base = (pbase_request)Request->data;
            if (!Base)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }
            pbase_request BaseCopy = (pbase_request)ExAllocatePool(NonPagedPool, sizeof(base_request));
            memcpy(BaseCopy, Base, sizeof(base_request));
            PVOID BaseAddress;
            Irp->IoStatus.Status = GetModuleBase(BaseCopy->pid, BaseCopy->name, &BaseAddress);
            if (NT_SUCCESS(Irp->IoStatus.Status))
                Base->handle = BaseAddress;
            ExFreePool(BaseCopy);
            break;
        }
        case init_fake:
        {
            pfake_init Fake = (pfake_init)Request->data;
            if (!Fake)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = InitFakeProcess(Fake->pid);
            break;
        }
        case read_memory:
        {
            pread_request Read = (pread_request)Request->data;
            if (!Read)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }
            SIZE_T read;
			Irp->IoStatus.Status = readprocessmemory(Read->BaseAddress, Read->buffer, Read->size, &read);
			// Irp->IoStatus.Status = FK_ReadMemory(Read->BaseAddress, Read->buffer, Read->size);
            break;
        }
        case call_entry:
        {
            pcall_entry_request Call = (pcall_entry_request)Request->data;
            if (!Call)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = CallKernelFunction(
                Call->process_id,
                Call->address,
                Call->shellcode
            );
            break;
        }
        default:
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (NT_SUCCESS(Irp->IoStatus.Status))
            Irp->IoStatus.Information = OutputBufferLength;
        break;
    }
    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}