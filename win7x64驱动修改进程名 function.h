#pragma once
#include"driver.h"
typedef struct DymanicMemory
{
	PVOID64 pMemory;
	INT lenth;
}Memory;
PEPROCESS EnumProcess(PUCHAR* pString); //查询指定进程并返回PID
void ChangeProcessName(PEPROCESS pProcess);//彻底改变进程名
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
KIRQL WPOFFx64();
void WPONx64(KIRQL irql);
void ChangePath(PEPROCESS pProcess);//改变文件路径
int judgeStringLen(WCHAR* string);//判断总共所占字节数,包括空字符
//Memory ReadProcessMemory(PEPROCESS pProcess, PVOID addr, INT lenth);
//NTSTATUS WriteProcessMemory(PEPROCESS pProcess, PVOID addr, PVOID buffer, INT lenth);
void FindStringAndChange(PEPROCESS pProcess, WCHAR* string, WCHAR* object);
