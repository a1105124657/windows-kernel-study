/*
有很多硬编码,每个系统都不一样.比如需要自己用IDA分析内核文件和NTDLL.DLL找到服务ID
*/

#include"driver.h"
typedef struct _SERVICE_DESCIPTOR_TABLE
{
	ULONG* ServiceTableBase;//ssdt的地址
	ULONG* ServiceCounter;//调用次数,一般是0
	ULONG NumberOfService;//ssdt中服务个数
	ULONG* ParamTableBase;//系统服务参数表
}SSDT,*pSSDT;
extern SSDT __declspec(dllimport) KeServiceDescriptorTable;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path)
{
	driver->DriverUnload = unloadDriver;
	//获取三个关键函数的地址
	pNtOpenProcess = (ULONG*)*(ULONG*)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + NtOpenProcessID * 4);
	pNtReadVirtualMemory = (ULONG*)*(ULONG*)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + NtReadVirtualMemoryID * 4);
	pNtWriteVirtualMemory = (ULONG*)*(ULONG*)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + NtWriteVirtualMemoryID * 4);
	//保存未hook前的字节
	oldByte1 = *(DWORD32*)((ULONG)pNtReadVirtualMemory + 3);
	oldByte2 = *(DWORD32*)((ULONG)pNtWriteVirtualMemory + 3);
	jmpAddr1 = (ULONG*)((ULONG)pNtReadVirtualMemory + 7);
	jmpAddr2 = (ULONG*)((ULONG)pNtWriteVirtualMemory + 7);
	PageProOff();
	(ULONG*)*(ULONG*)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + NtReadVirtualMemoryID * 4) = (ULONG*)myNtReadProcessMemory;
	(ULONG*)*(ULONG*)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + NtWriteVirtualMemoryID * 4) = (ULONG*)myNtWriteProcessMemory;
	//找到真正的函数地址
	PageProOn();
	UNICODE_STRING addr;
	RtlInitUnicodeString(&addr, L"ObOpenObjectByPointer");
	jmpAddr3 = MmGetSystemRoutineAddress(&addr);
	//实现hook
	hookAddr = (DWORD32*)((ULONG)pNtOpenProcess + 0x646B7);		
	PageProOff();
	*hookAddr = 0xe990; //内存中位90e9
	DWORD32* p_addr = (DWORD32*)((ULONG)hookAddr + 2);
	*p_addr = (ULONG)myNtOpenProcess-(ULONG)hookAddr-6;
	jmpAddr4 = (PVOID)((ULONG)hookAddr + 0xB);   
	PageProOn();
	return STATUS_SUCCESS;
}

