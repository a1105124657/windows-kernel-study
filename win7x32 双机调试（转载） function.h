#pragma once
#include <ntddk.h>
#include "ntimage.h"

//------------------------------------------------------------------------------------------特征码搜索 start---------------------
//                        地址              精准特征码       模糊特征码
BOOLEAN bCompare(const UCHAR* pData, const UCHAR* bMask, const char* szMask);

//                      开始地址       长度        精准特征码     模糊特征码
ULONG FindPattern(ULONG dwdwAdd, ULONG dwLen, UCHAR* bMask, char* szMask);
//------------------------------------------------------------------------------------------特征码搜索 end ---------------------

//取 KdpTrap 函数地址
ULONG_PTR GetKdpTrapAddress();

//取 KdpStub 函数地址
ULONG_PTR GetKdpStubAddress();

//取 KiDispatchException 函数地址
ULONG_PTR GetKiDispatchExceptionAddress();

//取 KiDebugRoutine 全局变量地址
ULONG_PTR GetKiDebugRoutineAddress();
