#pragma once
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
const int XOR_KEY{ 8 };

typedef void  (WINAPI* typeSleep)(
    DWORD dwMilis
    );

typedef DWORD(NTAPI* typeNtFlushInstructionCache)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG NumberOfBytesToFlush
    );

typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;

enum TypeOfFluctuation
{
    NoFluctuation = 0,
    FluctuateToRW,
    FluctuateToNA,
};

struct FluctuationMetadata
{
    LPVOID shellcodeAddr;
    SIZE_T shellcodeSize;
    bool currentlyEncrypted;
    DWORD encodeKey1;
    DWORD encodeKey2;
    DWORD protect;
};

struct HookedSleep
{
    typeSleep origSleep;
    BYTE    sleepStub[16];
};

struct HookTrampolineBuffers
{
    // (Input) Buffer containing bytes that should be restored while unhooking.
    BYTE* originalBytes;
    DWORD originalBytesSize;

    // (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
    BYTE* previousBytes;
    DWORD previousBytesSize;
};


template<class... Args>
void log(Args... args)
{
    std::stringstream oss;
    (oss << ... << args);

    std::cout << oss.str() << std::endl;
}

static const DWORD Shellcode_Memory_Protection = PAGE_EXECUTE_READ;

bool hookSleep();
bool iS(std::vector<uint8_t>& shellcode, HandlePtr& thread);
bool readShellcode(const char* path, std::vector<uint8_t>& shellcode);
std::vector<MEMORY_BASIC_INFORMATION> collectMemoryMap(HANDLE hProcess, DWORD Type = MEM_PRIVATE | MEM_MAPPED);
void iSF(const LPVOID caller);
bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers = NULL);
void xor32(uint8_t* buf, size_t bufSize, uint32_t xorKey);
bool iST(LPVOID address);
void SED(LPVOID callerAddress);
void relocateShellcode(const LPVOID caller, LPVOID addressOfRetAddr);
typedef void* (*tNtVirtual) (HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T  NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
tNtVirtual oNtVirtual;

void WINAPI MySleep(DWORD _dwMilliseconds);