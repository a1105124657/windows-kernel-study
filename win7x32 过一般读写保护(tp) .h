#include<ntifs.h>
#include<ntdef.h>
#define NtOpenProcessID 0xBE
#define NtReadVirtualMemoryID 0x115   
#define NtWriteVirtualMemoryID 0x18f
ULONG* pNtOpenProcess;
ULONG* pNtReadVirtualMemory;//存储着函数地址
ULONG* pNtWriteVirtualMemory;//同上
DWORD32 jmpAddr1;
DWORD32 jmpAddr2;
PVOID jmpAddr3;
PVOID jmpAddr4;
DWORD32 oldByte1;//存储未被hook的4个字节
DWORD32 oldByte2;//同上
SHORT* hookAddr;
void PageProOff();
void PageProOn();
void Sleep(ULONG n);
void myNtReadProcessMemory();
void myNtWriteProcessMemory();
void myNtOpenProcess();
void unloadDriver(PDRIVER_OBJECT driver)
{
	DbgPrint("驱动卸载成功");
}
void PageProOff()//去除页面保护
{
	_asm
	{
		cli
		push    eax
		mov        eax, cr0
		and eax,   not 0x10000
		mov        cr0, eax
		pop        eax
	}
}
void PageProOn()
{
	__asm
	{
		push    eax
		mov        eax, cr0
		or eax, 0x10000
		mov        cr0, eax
		pop        eax
		sti
	}
}
void Sleep(ULONG n)
{
	LARGE_INTEGER time;
	time.QuadPart = -10 * 1000 * 1000;
	time.QuadPart *= n;
	KeDelayExecutionThread(KernelMode, FALSE, &time);
}
_declspec(naked) void myNtReadProcessMemory()
{
	_asm
	{
		push 0x18
		push oldByte1
		jmp jmpAddr1
	}
}
_declspec(naked) void myNtWriteProcessMemory()
{
	_asm
	{
		push 0x18
		push oldByte2
		jmp jmpAddr2
	}
}
_declspec(naked) void myNtOpenProcess()
{
	_asm
	{
		push dword ptr[ebp - 0F0h]
		call jmpAddr3
		jmp  jmpAddr4
	}
}
