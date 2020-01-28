#include "Function.h"

//------------------------------------------------------------------------------------------特征码搜索 start---------------------
/* 调用实例

ULONG ulAddr = 0x********;
ulAddr = FindPattern(ulAddr, 512, "\x80\x3d\x6c\x29\xfb\x83\x00\x74\x12\xa1", "xx?????xxx");
if (ulAddr != 0)
{
	KdPrint(("搜索到的地址:%08x\r\n", ulAddr));
}else{
	KdPrint(("搜索失败！"));
}
*/

//                        地址              精准特征码       模糊特征码
BOOLEAN bCompare(const UCHAR* pData, const UCHAR* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)   return 0;
	return (*szMask) == NULL;
}

//                      开始地址       长度        精准特征码     模糊特征码
ULONG FindPattern(ULONG dwdwAdd, ULONG dwLen, UCHAR* bMask, char* szMask)
{
	for (ULONG i = 0; i < dwLen; i++)
		if (bCompare((UCHAR*)(dwdwAdd + i), bMask, szMask))  return (ULONG)(dwdwAdd + i);
	return 0;
}
//------------------------------------------------------------------------------------------特征码搜索 end ---------------------


//取 KdpTrap 函数地址
ULONG_PTR GetKdpTrapAddress()
{

	UNICODE_STRING uniKeUpdateRunTime;
	ULONG ulAddr;

	RtlInitUnicodeString(&uniKeUpdateRunTime, L"KeEnterKernelDebugger");			//字符串初始化
	ulAddr = (ULONG)MmGetSystemRoutineAddress(&uniKeUpdateRunTime);					//取 KeEnterKernelDebugger 函数地址

	//特征码定位 KdInitSystem
	//83f1dfc6 50              push    eax
	//83f1dfc7 50              push    eax
	//83f1dfc8 e83dc12400      call    nt!KdInitSystem(8416a10a)

	ulAddr = FindPattern(ulAddr, 256, "\x50\x50\xe8", "xxx");

	if (ulAddr != 0)
	{
		ulAddr += 2;
		//KdPrint(("KdInitSystem地址:%08x\r\n", ulAddr));
		ulAddr = ulAddr + *(PULONG)((PUCHAR)ulAddr + 1) + 5;
		//KdPrint(("计算后的 KdCheckForDebugBreak 地址:%08x\r\n", ulAddr));
	}
	else {
		KdPrint(("搜索 KdInitSystem 失败********************"));
		return 0;
	}


	/* 特征码定位 KdpTrap
	8416a3bd 53              push    ebx
	8416a3be e8977acdff      call    nt!KdDebuggerInitialize0(83e41e5a)
	8416a3c3 85c0            test    eax, eax
	8416a3c5 0f8c1a010000    jl      nt!KdInitSystem + 0x3db (8416a4e5)
	8416a3cb 803d18701b8400  cmp     byte ptr[nt!KdpDebuggerStructuresInitialized(841b7018)], 0
	8416a3d2 c705bc89fa83f2b41684 mov dword ptr[nt!KiDebugRoutine(83fa89bc)], offset nt!KdpTrap(8416b4f2)
	8416a3dc 7553            jne     nt!KdInitSystem + 0x327 (8416a431)
	8416a3de 56              push    esi
	8416a3df 6839b41684      push    offset nt!KdpTimeSlipDpcRoutine(8416b439)
	8416a3e4 680871f783      push    offset nt!KdpTimeSlipDpc(83f77108)
	*/

	ulAddr = FindPattern(ulAddr, 1000, "\xe8\x97\x7a\xcd\xff\x85\xc0\x0f", "x????xxx");

	if (ulAddr != 0)
	{
		ulAddr += 26;
		//KdPrint(("KdpTrap地址:%08x\r\n", ulAddr));
		return *(PULONG)ulAddr;
	}
	else {
		KdPrint(("搜索 KdpTrap 失败********************"));
		return 0;
	}
}

//取 KdpStub 函数地址
ULONG_PTR GetKdpStubAddress()
{
	UNICODE_STRING uniKeUpdateRunTime;
	ULONG ulAddr;

	RtlInitUnicodeString(&uniKeUpdateRunTime, L"KeEnterKernelDebugger");			//字符串初始化
	ulAddr = (ULONG)MmGetSystemRoutineAddress(&uniKeUpdateRunTime);					//取 KeEnterKernelDebugger 函数地址

	//特征码定位 KdInitSystem
	//83f1dfc6 50              push    eax
	//83f1dfc7 50              push    eax
	//83f1dfc8 e83dc12400      call    nt!KdInitSystem(8416a10a)

	ulAddr = FindPattern(ulAddr, 256, "\x50\x50\xe8", "xxx");

	if (ulAddr != 0)
	{
		ulAddr += 2;
		//KdPrint(("KdInitSystem地址:%08x\r\n", ulAddr));
		ulAddr = ulAddr + *(PULONG)((PUCHAR)ulAddr + 1) + 5;
		//KdPrint(("计算后的 KdCheckForDebugBreak 地址:%08x\r\n", ulAddr));
	}
	else {
		KdPrint(("搜索 KdInitSystem 失败********************"));
		return 0;
	}

	//特征码定位 KdpStub
	//83f167e9 e8021a2500            call    nt!KdpSuspendAllBreakpoints(841681f0)
	//83f167ee 881d2cedf983          mov     byte ptr[nt!KdDebuggerEnabled(83f9ed2c)], bl
	//83f167f4 c705bc39fa83af69f183  mov dword ptr[nt!KiDebugRoutine(83fa39bc)], offset nt!KdpStub(83f169af)
	//83f167fe 881dd402dfff          mov     byte ptr ds : [0FFDF02D4h], bl

	//8414a14d 833decef188400        cmp     dword ptr[nt!KdpDebuggerDataListHead(8418efec)], 0
	//8414a154 c705bc89f883afb9ef83  mov dword ptr[nt!KiDebugRoutine(83f889bc)], offset nt!KdpStub(83efb9af)
	//8414a15e c605913cf88300        mov     byte ptr[nt!KdBreakAfterSymbolLoad(83f83c91)], 0
	//8414a165 7571                  jne     nt!KdInitSystem + 0xce (8414a1d8)


	ulAddr = FindPattern(ulAddr, 100, "\x83\x3d\xec\xef\x18\x84\x00\xc7\x05", "xx?????xx");

	if (ulAddr != 0)
	{
		ulAddr += 13;
		//KdPrint(("KdpStub地址:%08x\r\n", *(PULONG)ulAddr));
		return *(PULONG)ulAddr;
	}
	else {
		KdPrint(("搜索 KdpStub 失败********************"));
		return 0;
	}
}


//取 KiDispatchException 函数地址
ULONG_PTR GetKiDispatchExceptionAddress()
{
	UNICODE_STRING uniKeUpdateRunTime;
	ULONG ulAddr;

	RtlInitUnicodeString(&uniKeUpdateRunTime, L"KiDeliverApc");			//字符串初始化
	ulAddr = (ULONG)MmGetSystemRoutineAddress(&uniKeUpdateRunTime);		//取 KiDeliverApc 函数地址

	/* 特征码定位 KdInitSystem
	83ee88d0 ff742414        push    dword ptr [esp+14h]
	83ee88d4 8b4d0c          mov     ecx,dword ptr [ebp+0Ch]
	83ee88d7 ff74241c        push    dword ptr [esp+1Ch]
	83ee88db ff742424        push    dword ptr [esp+24h]
	83ee88df ff74241c        push    dword ptr [esp+1Ch]
	83ee88e3 ff7510          push    dword ptr [ebp+10h]
	83ee88e6 e87f02f8ff      call    nt!KiInitializeUserApc (83e68b6a)
	83ee88eb 8b4750          mov     eax,dword ptr [edi+50h]
	83ee88ee 3b442424        cmp     eax,dword ptr [esp+24h]
	83ee88f2 7425            je      nt!KiDeliverApc+0x2e3 (83ee8919)
	*/

	ulAddr = FindPattern(ulAddr, 1000, "\xff\x74\x24\x1c\xff\x75\x10\xe8", "xx??xx?x");

	if (ulAddr != 0)
	{
		ulAddr += 7;
		//KdPrint(("KiInitializeUserApc地址:%08x\r\n", ulAddr));
		ulAddr = ulAddr + *(PULONG)((PUCHAR)ulAddr + 1) + 5;
		//KdPrint(("计算后的 KiInitializeUserApc 地址:%08x\r\n", ulAddr));
	}
	else {
		KdPrint(("搜索 KiInitializeUserApc 失败********************"));
		return 0;
	}

	/* 特征码定位 KiDispatchException
	83e68c9b 6a01            push    1
	83e68c9d 6a01            push    1
	83e68c9f 56              push    esi
	83e68ca0 ffb5fcfcffff    push    dword ptr [ebp-304h]
	83e68ca6 8d85acfcffff    lea     eax,[ebp-354h]
	83e68cac 50              push    eax
	83e68cad e82e320800      call    nt!KiDispatchException (83eebee0)
	83e68cb2 c745fcfeffffff  mov     dword ptr [ebp-4],0FFFFFFFEh
	83e68cb9 e8dade0400      call    nt!_SEH_epilog4_GS (83eb6b98)
	83e68cbe c21400          ret     14h
	*/

	ulAddr = FindPattern(ulAddr, 1000, "\x56\xff\xb5\xfc\xfc\xff\xff\x8d\x85\xac\xfc\xff\xff\x50\xe8", "xxx????xx????xx");

	if (ulAddr != 0)
	{
		ulAddr += 14;
		//KdPrint(("KiDispatchException地址:%08x\r\n", ulAddr));
		ulAddr = ulAddr + *(PULONG)((PUCHAR)ulAddr + 1) + 5;
		//KdPrint(("计算后的 KiDispatchException 地址:%08x\r\n", ulAddr));
		return ulAddr;
	}
	else {
		KdPrint(("搜索 KiDispatchException 失败********************"));
		return 0;
	}

}


//取 KiDebugRoutine 全局变量地址
ULONG_PTR GetKiDebugRoutineAddress()
{
	ULONG ulAddr;
	ulAddr = GetKiDispatchExceptionAddress();								//取 KiDispatchException 函数地址
	//KdPrint(("KiDispatchException地址:%08x\r\n", ulAddr));

	//---------------------------------------------------------------------------------------------------------------------第一处KiDebugRoutine
	//特征码定位KiDebugRoutine
	//83eb5027 ff15209bf683    call    dword ptr [nt!KiDebugRoutine (83f69b20)]
	//83eb502d 84c0            test    al,al
	//UCHAR szSig[8] = { 0xff, 0x15, '?', '?', '?', '?', 0x84, 0xc0 };

	ulAddr = FindPattern(ulAddr, 512, "\xff\x15\x20\x9b\xf6\x83\x84\xc0 ", "xx????xx");
	if (ulAddr != 0)
	{
		ulAddr += 2;
		//KdPrint(("搜到的地址:%08x\r\n", ulAddr));
		//KdPrint(("KiDebugRoutine地址:%08x\r\n", *(PULONG)ulAddr));
		return *(PULONG)ulAddr;
	}
	else {
		KdPrint(("搜索 KiDebugRoutine 失败********************"));
		return;
	}
}
