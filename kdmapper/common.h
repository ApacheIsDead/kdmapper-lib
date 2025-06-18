#pragma once
#pragma once
#ifdef _KERNEL_MODE
#include <ntddk.h>    // or #include <ntdef.h>
#else
#include <Windows.h>
#include <cstdint>
#endif
#define MAGIC 1337

typedef enum _OPERATION_TYPE
{
    OP_BASE = 0,
    OP_READ = 1,
    OP_WRITE = 2,
    OP_EXIT = 3,
    OP_MODULE_BASE = 4,
    OP_ALLOCATE_MEM = 5,
    OP_INJECT_APC = 6,
    OP_INJECT_DLL = 7
} OPERATION_TYPE;

#pragma pack(push, 8)
struct UM_Msg
{
    ULONG ProcId;
    ULONG pad1;//
    ULONGLONG address;
    OPERATION_TYPE opType; // 4 bytes
    ULONG pad2;
    ULONGLONG dataSize;
    UINT32 magic = MAGIC;
    BYTE data[256];
};
