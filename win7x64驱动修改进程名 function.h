#pragma once
#include"driver.h"
PEPROCESS EnumProcess(PUCHAR* pString); //查询指定进程并返回PID
void ChangeProcessName(PEPROCESS pProcess);//彻底改变进程名
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
KIRQL WPOFFx64();
void WPONx64(KIRQL irql);


