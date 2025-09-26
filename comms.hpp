#pragma once
#include <ntifs.h>
#include <cstdint>

typedef enum _request_codes
{
	init_driver = 0x358,
	get_base = 0x359,
	init_fake = 0x360,
	read_memory = 0x355,
	call_entry = 0x320,
	request_success = 0x22c,
	request_unique = 0x92b,
	request_unload = 0x93b,
}request_codes, * prequest_codes;

typedef struct _unload_request
{
	bool buffer;
}unload_request, * punload_request;

typedef struct _fake_init {
	HANDLE pid;
} fake_init, * pfake_init;

typedef struct _read_request {
	PVOID BaseAddress;
	PVOID buffer;
	SIZE_T size;
} read_request, * pread_request;

struct process_request_t
{
	ULONG process_id;
};

typedef struct _base_request {
	HANDLE pid;
	HANDLE handle;
	CHAR name[100];
} base_request, * pbase_request;

typedef struct _driver_init {
	bool init;
} driver_init, * pdriver_init;

typedef struct _call_entry_request
{
	HANDLE process_id;
	PVOID address;
	PVOID shellcode;

	BOOLEAN result;
} call_entry_request, * pcall_entry_request;

typedef struct _request_data
{
	uint32_t unique;
	request_codes code;
	void* data;
}request_data, * prequest_data;