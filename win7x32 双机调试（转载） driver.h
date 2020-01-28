#pragma once
#include <ntddk.h>
#include "ntimage.h"
#include "Function.h"

//KdpStub 函数地址变量存储
ULONG KdpStubAddr;

//KdpTrap 函数地址变量存储
ULONG KdpTrapAddr;

//KdDebuggerEnabled变量存储
BOOLEAN gKdDebuggerEnabled = TRUE;

//KdPitchDebugger变量存储
BOOLEAN gKdPitchDebugger = FALSE;

//KiDebugRoutine变量存储
ULONG gKiDebugRoutine = 0;

typedef struct _KTRAP_FRAME
{
	ULONG DbgEbp;
	ULONG DbgEip;
	ULONG DbgArgMark;
	ULONG DbgArgPointer;

	ULONG TempSegCs;
	ULONG TempEsp;

	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;

	ULONG SegGs;
	ULONG SegEs;
	ULONG SegDs;

	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;

	ULONG PreviousPreviousMode;

	PVOID ExceptionList;

	ULONG SegFs;

	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;

	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;

	ULONG HardwareEsp;
	ULONG HardwareSegSs;

	ULONG V86Es;
	ULONG V86Ds;
	ULONG V86Fs;
	ULONG V86Gs;

} KTRAP_FRAME;
//======================================================================================================================================

//恢复内存保护 
void PageProtectOn()
{
	__asm {
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}
}


//去掉内存保护
void PageProtectOff()
{
	__asm {
		cli
		mov  eax, cr0
		and eax, not 10000h
		mov  cr0, eax
	}
}

//======================================================================================================================================

//转移win7中的KdDebuggerEnabled和KdPitchDebugger变量
void MoveVariable_Win7()
{
	ULONG ulAddr, ulAddr2;
	UNICODE_STRING uniKeUpdateRunTime;

	//----------------------------------------------------------------------------------------------------------------改写KeUpdateRunTime中的KdDebuggerEnabled 

	//得到原内核的KeUpdateRunTime地址
	RtlInitUnicodeString(&uniKeUpdateRunTime, L"KeUpdateRunTime");			//字符串初始化
	ulAddr = (ULONG)MmGetSystemRoutineAddress(&uniKeUpdateRunTime);			//取 KeUpdateRunTime 函数地址


	//定位KdDebuggerEnabled
	//特征码
	//83ec9082 803d6c29fb8300  cmp     byte ptr [nt!KdDebuggerEnabled (83fb296c)],0
	//83ec9089 7412            je      nt!KeUpdateRunTime+0x164 (83ec909d)
	//83ec908b a1745ff883      mov     eax,dword ptr [nt!KiPollSlot (83f85f74)]

	ulAddr = FindPattern(ulAddr, 512, "\x80\x3d\x6c\x29\xfb\x83\x00\x74\x12\xa1", "xx?????xxx");

	if (ulAddr != 0)
	{
		ulAddr += 2;
		KdPrint(("搜索01地址:%08x\r\n", ulAddr));
		PageProtectOff();
		*(PULONG)ulAddr = (ULONG)&gKdDebuggerEnabled;
		PageProtectOn();
		KdPrint(("改写01完成！"));
	}
	else {
		KdPrint(("搜索01失败********************"));
		return;
	}


	//----------------------------------------------------------------------------------------------------------------改写KdCheckForDebugBreak中的KdDebuggerEnabled

	//得到KdCheckForDebugBreak地址
	//特征码
	//83ec9098 e80c000000      call    nt!KdCheckForDebugBreak (83ec90a9)
	//83ec909d 5f              pop     edi

	ulAddr = FindPattern(ulAddr, 256, "\xe8\xc0\x00\x00\x00\x5f", "x????x");
	if (ulAddr != 0)
	{
		KdPrint(("搜索02地址:%08x\r\n", ulAddr));
	}
	else {
		KdPrint(("搜索02失败********************"));
		return;
	}

	ulAddr = ulAddr + *(PULONG)((PUCHAR)ulAddr + 1) + 5;
	KdPrint(("计算后的 KdCheckForDebugBreak 地址:%08x\r\n", ulAddr));


	//记录KdCheckForDebugBreak函数地址 用于KdPitchDebugger变量的处理
	ulAddr2 = ulAddr;


	//特征码定位KdDebuggerEnabled
	//83ec90b2 803d6c29fb8300  cmp     byte ptr [nt!KdDebuggerEnabled (83fb296c)],0
	//83ec90b9 7410            je      nt!KdCheckForDebugBreak+0x22 (83ec90cb)
	//83ec90bb e81f000000      call    nt!KdPollBreakIn (83ec90df)

	ulAddr = FindPattern(ulAddr, 256, "\x80\x3d\x6c\x29\xfb\x83\x00\x74\x10\xe8", "xx?????xxx");

	if (ulAddr != 0)
	{
		ulAddr += 2;
		KdPrint(("搜索03地址:%08x\r\n", ulAddr));
		PageProtectOff();
		*(PULONG)ulAddr = (ULONG)&gKdDebuggerEnabled;
		PageProtectOn();
		KdPrint(("改写03完成！"));
	}
	else {
		KdPrint(("搜索03失败********************"));
		return;
	}

	//----------------------------------------------------------------------------------------------------------------改写KdCheckForDebugBreak中的KdPitchDebugger

	//定位KdPitchDebugger变量
	//由于KdPitchDebugger变量在函数开头偏移2处 所以直接偏移定位KdPitchDebugger
	//83eb30a9 803d270df68300  cmp     byte ptr [nt!KdPitchDebugger (83f60d27)],0
	//83eb30b0 7519            jne     nt!KdCheckForDebugBreak+0x22 (83eb30cb)
	ulAddr2 += 2;

	KdPrint(("搜索04地址:%08x\r\n", ulAddr2));

	//改写KdPitchDebugger变量
	PageProtectOff();
	*(PULONG)ulAddr2 = (ULONG)&gKdPitchDebugger;
	PageProtectOff();


	//----------------------------------------------------------------------------------------------------------------改写KdPollBreakIn中的KdDebuggerEnabled

	//得到KdPollBreakIn地址
	//特征码
	//83ebe0bb e81f000000      call    nt!KdPollBreakIn (83ebe0df)
	//83ebe0c0 84c0            test    al,al

	ulAddr = FindPattern(ulAddr, 256, "\xe8\x1f\x00\x00\x00\x84\xc0", "x????xx");
	if (ulAddr != 0)
	{
		KdPrint(("搜索05地址:%08x\r\n", ulAddr));
	}
	else {
		KdPrint(("搜索05失败********************"));
		return;
	}

	ulAddr = ulAddr + *(PULONG)((PUCHAR)ulAddr + 1) + 5;
	KdPrint(("计算后的 KdPollBreakIn 地址:%08x\r\n", ulAddr));


	//记录KdPollBreakIn函数地址 用于KdPitchDebugger变量的处理
	ulAddr2 = ulAddr;

	//特征码定位KdDebuggerEnabled
	//83ebe0f7 885dff          mov     byte ptr [ebp-1],bl
	//83ebe0fa 381d6c79fa83    cmp     byte ptr [nt!KdDebuggerEnabled (83fa796c)],bl
	//83ebe100 0f84c0000000    je      nt!KdPollBreakIn+0xe7 (83ebe1c6)

	ulAddr = FindPattern(ulAddr, 256, "\x88\x5d\xff\x38\x1d\x6c\x79\xfa\x83\x0f\x84", "xxxxx????xx");
	if (ulAddr != 0)
	{
		ulAddr += 5;
		KdPrint(("搜索06地址:%08x\r\n", ulAddr));
		PageProtectOff();
		*(PULONG)ulAddr = (ULONG)&gKdDebuggerEnabled;
		PageProtectOn();
		KdPrint(("改写06完成！"));
	}
	else {
		KdPrint(("搜索06失败********************"));
		return;
	}

	//----------------------------------------------------------------------------------------------------------------改写KdPollBreakIn中的KdPitchDebugger

	//特征码定位KdPitchDebugger
	//83eb30e6 33db            xor     ebx,ebx
	//83eb30e8 381d270df683    cmp     byte ptr [nt!KdPitchDebugger (83f60d27)],bl
	//83eb30ee 7407            je      nt!KdPollBreakIn+0x18 (83eb30f7)

	ulAddr2 = FindPattern(ulAddr2, 256, "\x33\xdb\x38\x1d\x27\x0d\xf6\x83\x74\x07", "xxxx????xx");

	if (ulAddr2 != 0)
	{
		ulAddr2 += 4;
		KdPrint(("搜索07地址:%08x\r\n", ulAddr2));
		PageProtectOff();
		*(PULONG)ulAddr2 = (ULONG)&gKdPitchDebugger;
		PageProtectOn();
		KdPrint(("改写07完成！"));
	}
	else {
		KdPrint(("搜索07失败********************"));
		return;
	}

}

//======================================================================================================================================

//转移win7中的KiDebugRoutine变量
void MoveKiDebugRoutine_Win7()
{
	ULONG ulAddr;

	ulAddr = GetKdpTrapAddress();											//取 KdpTrap 函数地址
	KdPrint(("KdpTrap地址:%08x\r\n", ulAddr));

	gKiDebugRoutine = ulAddr;												//设置自定义的 KiDebugRoutine 变量

	ulAddr = GetKiDispatchExceptionAddress();								//取 KiDispatchException 函数地址
	KdPrint(("KiDispatchException地址:%08x\r\n", ulAddr));

	//---------------------------------------------------------------------------------------------------------------------第一处KiDebugRoutine
	//特征码定位KiDebugRoutine
	//83eb5027 ff15209bf683    call    dword ptr [nt!KiDebugRoutine (83f69b20)]
	//83eb502d 84c0            test    al,al
	//UCHAR szSig[8] = { 0xff, 0x15, '?', '?', '?', '?', 0x84, 0xc0 };

	ulAddr = FindPattern(ulAddr, 512, "\xff\x15\x20\x9b\xf6\x83\x84\xc0 ", "xx????xx");
	if (ulAddr != 0)
	{
		ulAddr += 2;
		KdPrint(("搜索08地址:%08x\r\n", ulAddr));
		PageProtectOff();
		*(PULONG)ulAddr = (ULONG)&gKiDebugRoutine;
		PageProtectOn();
		KdPrint(("改写08完成！"));
	}
	else {
		KdPrint(("搜索08失败********************"));
		return;
	}


	//---------------------------------------------------------------------------------------------------------------------第二处KiDebugRoutine
	//特征码与前边一样

	ulAddr = FindPattern(ulAddr, 512, "\xff\x15\x20\x9b\xf6\x83\x84\xc0 ", "xx????xx");
	if (ulAddr != 0)
	{
		ulAddr += 2;
		KdPrint(("搜索09地址:%08x\r\n", ulAddr));
		PageProtectOff();
		*(PULONG)ulAddr = (ULONG)&gKiDebugRoutine;
		PageProtectOn();
		KdPrint(("改写09完成！"));
	}
	else {
		KdPrint(("搜索09失败********************"));
		return;
	}

	//---------------------------------------------------------------------------------------------------------------------第三处KiDebugRoutine
	//特征码与前边一样

	ulAddr = FindPattern(ulAddr, 512, "\xff\x15\x20\x9b\xf6\x83\x84\xc0 ", "xx????xx");
	if (ulAddr != 0)
	{
		ulAddr += 2;
		KdPrint(("搜索10地址:%08x\r\n", ulAddr));
		PageProtectOff();
		*(PULONG)ulAddr = (ULONG)&gKiDebugRoutine;
		PageProtectOn();
		KdPrint(("改写10完成！"));
	}
	else {
		KdPrint(("搜索10失败********************"));
		return;
	}

}

//======================================================================================================================================

typedef KTRAP_FRAME* PKTRAP_FRAME;
typedef KTRAP_FRAME* PKEXCEPTION_FRAME;

//定义kdpStub用于后面进行hook替换
typedef BOOLEAN(__stdcall* KDPSTUB)(
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChance);


//建立一个自己的KdpStub用于进行过滤
BOOLEAN __stdcall MyKdpStub(
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChance
)
{


	//return ((KDPSTUB)KdpStubAddr)(TrapFrame, ExceptionFrame, ExceptionRecord, ContextRecord, PreviousMode, SecondChance);

	//如果检测到是TP的登录进程,在这个地方就返回KdpStub   174 XP 16C WIN7
	PEPROCESS curproc = (char*)PsGetCurrentProcess() + 0x16C;

	if (strstr(curproc, "TASLogin.exe") != 0 || strstr(curproc, "TPHelper.exe") != 0 || strstr(curproc, "GameLoader.exe") != 0 || strstr(curproc, "DNF.exe") != 0)
	{
		return ((KDPSTUB)KdpStubAddr)
			(
				TrapFrame, \
				ExceptionFrame, \
				ExceptionRecord, \
				ContextRecord, \
				PreviousMode, \
				SecondChance\
				);
	}

	//其他情况直接返回
	return ((KDPSTUB)KdpTrapAddr)
		(
			TrapFrame, \
			ExceptionFrame, \
			ExceptionRecord, \
			ContextRecord, \
			PreviousMode, \
			SecondChance\
			);


}





//HOOK KiDebugRoutine 过蓝屏
BOOLEAN ChangeKiDebugRoutineAddr()
{
	ULONG ulAddr;
	ulAddr = GetKiDebugRoutineAddress();
	KdPrint(("KiDebugRoutine地址:%08x\r\n", ulAddr));


	KdpStubAddr = GetKdpStubAddress();
	KdPrint(("KdpStub地址:%08x\r\n", KdpStubAddr));

	KdpTrapAddr = GetKdpTrapAddress();
	KdPrint(("KdpTrap地址:%08x\r\n", KdpTrapAddr));



	PageProtectOff();
	*(PVOID*)ulAddr = (PVOID)MyKdpStub;
	PageProtectOn();

}
