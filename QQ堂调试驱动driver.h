#include"struct.h"
typedef struct _SERVICE_DESCIPTOR_TABLE
{
	ULONG* ServiceTableBase;//ssdt的地址
	ULONG* ServiceCounter;//调用次数,一般是0
	ULONG NumberOfService;//ssdt中服务个数
	ULONG* ParamTableBase;//系统服务参数表
}SSDT, * pSSDT;
extern SSDT __declspec(dllimport) KeServiceDescriptorTable;
typedef PMDL(*p_old_IoAllocateMdl)(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);
#define malloc(count) ExAllocatePoolWithTag(NonPagedPool, count, 'tag1')
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
int myKdDebuggerEnabled = 1;
int* p_myKdDebuggerEnabled = &myKdDebuggerEnabled;
int myKdPitchDebugger = 0;
int* p_myKdPitchDebugger = &myKdPitchDebugger;
PVOID KdEnteredDebugger = (PVOID)0x83fafd24;
ULONG p_KiAttachProcess = 0x83ecd8d9;
p_old_IoAllocateMdl old_IoAllocateMdl = NULL;
KTIMER   Timer;// 注意要定义全局变量
KDPC     DPC;//注意要定义全局变量
LARGE_INTEGER DueTime;
char code[5] = { 0x8b,0xff,0x55,0x8b,0xec };
KTIMER TimerObject;
KDPC DpcObject;
LARGE_INTEGER NextTime;
ULONG* ValidAccessMaskAdr = 0x855D36AC;
BOOLEAN flag =FALSE;
PDRIVER_OBJECT driver_global = NULL;
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
			and eax, not 0x10000
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


PMDL My_IoAllocateMdl(
	_In_opt_ __drv_aliasesMem PVOID VirtualAddress,
	_In_ ULONG Length,
	_In_ BOOLEAN SecondaryBuffer,
	_In_ BOOLEAN ChargeQuota,
	_Inout_opt_ PIRP Irp
) {
	if (VirtualAddress == KdEnteredDebugger)
	{
		VirtualAddress = (PVOID)((ULONG)KdEnteredDebugger + 0x30);
#ifndef  _DEBUG
		DbgPrint("%p", VirtualAddress);
#endif //  _DEBUG
		
	}
	return old_IoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
}
void kill_read_write_token()
{
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
	*p_addr = (ULONG)myNtOpenProcess - (ULONG)hookAddr - 6;
	jmpAddr4 = (PVOID)((ULONG)hookAddr + 0xB);
	PageProOn();
}
void kill_double_machine()
{
	/*
kd> kn
# ChildEBP RetAddr
00 83f72a80 83ec510b nt!RtlpBreakWithStatusInstruction
01 83f72a88 83ec50dd nt!KdCheckForDebugBreak+0x22
83ec50e9 803d273df78300  cmp     byte ptr [nt!KdPitchDebugger (83f73d27)],0
83ec50f0 7519            jne     nt!KdCheckForDebugBreak+0x22 (83ec510b)
83ec50f2 803d2cfdfa8300  cmp     byte ptr [nt!KdDebuggerEnabled (83fafd2c)],0
02 83f72ab8 83ec4f6b nt!KeUpdateRunTime+0x164 83ec50c2 803d2cfdfa8300  cmp     byte ptr [nt!KdDebuggerEnabled (83fafd2c)],0
03 83f72b14 83ec9c17 nt!KeUpdateSystemTime+0x613  83ec4d6b 803d2cfdfa8300  cmp     byte ptr [nt!KdDebuggerEnabled (83fafd2c)],0
04 83f72b14 8f90f5d6 nt!KeUpdateSystemTimeAssist+0x13
	*/
	//KdDebuggerEnabled置为0之后windbg就收不到消息
	PageProOff();
	memset(KdDebuggerEnabled, 0, 1);
	memcpy(0x83ec4d6d, &p_myKdDebuggerEnabled, 4);
	memcpy(0x83ec50c4, &p_myKdDebuggerEnabled, 4);
	memcpy(0x83ec50eb, &p_myKdPitchDebugger, 4);
	memcpy(0x83ec50f4, &p_myKdDebuggerEnabled, 4);
	/*
	kd> u KdPollBreakIn l20
nt!KdPollBreakIn:
83ec511f 8bff            mov     edi,edi
83ec5121 55              push    ebp
83ec5122 8bec            mov     ebp,esp
83ec5124 51              push    ecx
83ec5125 53              push    ebx
83ec5126 33db            xor     ebx,ebx
83ec5128 381d273df783    cmp     byte ptr [nt!KdPitchDebugger (83f73d27)],bl
83ec512e 7407            je      nt!KdPollBreakIn+0x18 (83ec5137)
83ec5130 32c0            xor     al,al
83ec5132 e9d2000000      jmp     nt!KdPollBreakIn+0xea (83ec5209)
83ec5137 885dff          mov     byte ptr [ebp-1],bl
83ec513a 381d2cfdfa83    cmp     byte ptr [nt!KdDebuggerEnabled (83fafd2c)],bl
83ec5140 0f84c0000000    je      nt!KdPollBreakIn+0xe7 (83ec5206)
83ec5146 56              push    esi
83ec5147 57              push    edi
83ec5148 e837280000      call    nt!KeDisableInterrupts (83ec7984)
83ec514d 53              push    ebx
83ec514e 8845fe          mov     byte ptr [ebp-2],al
83ec5151 e853c7fbff      call    nt!KeGetCurrentProcessorNumberEx (83e818a9)
83ec5156 8d3485a0fcfa83  lea     esi,nt!KdLogBuffer (83fafca0)[eax*4]
83ec515d 8b06            mov     eax,dword ptr [esi]
83ec515f 3bc3            cmp     eax,ebx
83ec5161 741a            je      nt!KdPollBreakIn+0x5e (83ec517d)
83ec5163 8b08            mov     ecx,dword ptr [eax]
83ec5165 c1e104          shl     ecx,4
83ec5168 8d4c0108        lea     ecx,[ecx+eax+8]
83ec516c 0f31            rdtsc
83ec516e 8901            mov     dword ptr [ecx],eax
83ec5170 895104          mov     dword ptr [ecx+4],edx
83ec5173 c7410802000000  mov     dword ptr [ecx+8],2
83ec517a 89590c          mov     dword ptr [ecx+0Ch],ebx
83ec517d 381d44fdfa83    cmp     byte ptr [nt!KdpContext+0x4 (83fafd44)],bl
*/
	memcpy(0x83ec512A, &p_myKdPitchDebugger, 4);
	memcpy(0x83ec513c, &p_myKdDebuggerEnabled, 4);
	PageProOn();
	/*
	kd> u IoAllocateMdl
nt!IoAllocateMdl:
83edf4f5 8bff            mov     edi,edi
83edf4f7 55              push    ebp
83edf4f8 8bec            mov     ebp,esp
83edf4fa 83ec10          sub     esp,10h
83edf4fd 8b550c          mov     edx,dword ptr [ebp+0Ch]
83edf500 8365fc00        and     dword ptr [ebp-4],0
83edf504 53              push    ebx
83edf505 57              push    edi
	*/

	//hook IoAllocateMdl
	PageProOff();
	old_IoAllocateMdl = malloc(10);
	if (old_IoAllocateMdl == NULL)
		return STATUS_UNSUCCESSFUL;
	RtlZeroMemory(old_IoAllocateMdl, 10);
	//返回值检查

	/*
	eb old_IoAllocateMdl 8b
eb old_IoAllocateMdl+1 ff
eb old_IoAllocateMdl+2 55
eb old_IoAllocateMdl+3 8b
eb old_IoAllocateMdl+4 ec
eb old_IoAllocateMdl+5 e9
ed old_IoAllocateMdl+6 B27494

u old_IoAllocateMdl
bp IoAllocateMdl
	*/
	//处理KdEnterDebugger
	char code_2[5] = { 0xe9 };
	char code_1[10] = { 0x8b,0xff,0x55,0x8b, 0xec,0xe9,0,0,0,0 };
	DWORD32 shift_1 = (ULONG)My_IoAllocateMdl - (ULONG)IoAllocateMdl - 5;
	memcpy(code_2 + 1, &shift_1, 4);
	memcpy(0x83edf4f5, code_2, 5);//inline hook jmp到我的函数
	//((ULONG)IoAllocateMdl+5-(ULONG)old_IoAllocateMdl-5+5
	DWORD32 shift_2 = (ULONG)IoAllocateMdl - (ULONG)old_IoAllocateMdl - 5;
	memcpy(code_1 + 6, &shift_2, 4);
	memcpy(old_IoAllocateMdl, code_1, 10);

	//将KiDebugRoutine指向了KdpStub  hook KdpStub，让他跳转到KdpTrap
	/*
	PAGEKD:0072C3CB                 cmp     ds:_KdpDebuggerStructuresInitialized, 0
PAGEKD:0072C3D2                 mov     ds:_KiDebugRoutine, offset _KdpTrap@24 ; KdpTrap(x,x,x,x,x,x)
	kd> u KdpStub
nt!KdpStub:
83f279af 8bff            mov     edi,edi
	kd> u KdpTrap
nt!KdpTrap:
841774f2 8bff            mov     edi,edi
kd> dd KiDebugRoutine
83fb49bc  841774f2 83ec8d9c 00000000 00000191
dd KiDebugRoutine
807dc988  83f279af 83f279af fca73fb8 ff4d6fd6
kd> u KdInitSystem l150
nt!KdInitSystem:
8417610a 8bff            mov     edi,edi
84176154 c705bc49fb83af79f283 mov dword ptr [nt!KiDebugRoutine (83fb49bc)],offset nt!KdpStub (83f279af)
	*/
	DWORD32* KiDebugRoutine = *(DWORD32*)0x84176156;
	DWORD32* p_temp = 0x83f279af;
	memcpy(&KiDebugRoutine, &p_temp, 4);
	DWORD32 shift_3 = (DWORD32)(0x841774f2 - 0x83f279af) - 5;
	char code_3[5] = { 0xe9,0,0,0,0 };
	memcpy(code_3 + 1, &shift_3, 4);
	memcpy(0x83f279af, code_3, 5);
	PageProOn();
}

LDR_DATA_TABLE_ENTRY* search_kernel_module_and_hide(PDRIVER_OBJECT driver,wchar_t * name)
{
	UNICODE_STRING name_string;
	RtlInitUnicodeString(&name_string, name);

	LDR_DATA_TABLE_ENTRY* pDataTableEntry, * pTempDataTableEntry;

	//双循环链表定义
	PLIST_ENTRY                          pList;

	//指向驱动对象的DriverSection

	pDataTableEntry = (LDR_DATA_TABLE_ENTRY*)driver->DriverSection;

	//判断是否为空
	if (!pDataTableEntry)
	{
		return;
	}

	//开始遍历驱动对象链表

	//得到链表地址
	pList = pDataTableEntry->InLoadOrderLinks.Flink;

	
	//判断是否等于头部
	do
	{
		pTempDataTableEntry = (LDR_DATA_TABLE_ENTRY*)pList;
		
		if (!RtlCompareUnicodeString(&pTempDataTableEntry->BaseDllName, &name_string, 0)) {
			pTempDataTableEntry->InLoadOrderLinks.Flink->Blink = pTempDataTableEntry->InLoadOrderLinks.Blink;
			pTempDataTableEntry->InLoadOrderLinks.Blink->Flink = pTempDataTableEntry->InLoadOrderLinks.Flink;
			return pTempDataTableEntry;
		}
		pList = pList->Flink;
	} while (pList != &pDataTableEntry->InLoadOrderLinks);
		return NULL;
}
void* search_kernel_module_and_hide_template()
{
	UNICODE_STRING name_string;
	RtlInitUnicodeString(&name_string, L"TesSafe.sys");

	LDR_DATA_TABLE_ENTRY* pDataTableEntry, * pTempDataTableEntry;

	//双循环链表定义
	PLIST_ENTRY                          pList;

	//指向驱动对象的DriverSection

	pDataTableEntry = (LDR_DATA_TABLE_ENTRY*)driver_global->DriverSection;

	//判断是否为空
	if (!pDataTableEntry)
	{
		return;
	}

	//开始遍历驱动对象链表

	//得到链表地址
	pList = pDataTableEntry->InLoadOrderLinks.Flink;


	//判断是否等于头部
	do
	{
		pTempDataTableEntry = (LDR_DATA_TABLE_ENTRY*)pList;

		if (!RtlCompareUnicodeString(&pTempDataTableEntry->BaseDllName, &name_string, 0)) {
			flag = TRUE;
			return;
		}
		pList = pList->Flink;
	} while (pList != &pDataTableEntry->InLoadOrderLinks);
	return;
}
void traverse_kernel_module(PDRIVER_OBJECT driver) {
	LDR_DATA_TABLE_ENTRY* pDataTableEntry, * pTempDataTableEntry;

	//双循环链表定义
	PLIST_ENTRY                          pList;

	//指向驱动对象的DriverSection

	pDataTableEntry = (LDR_DATA_TABLE_ENTRY*)driver->DriverSection;

	//判断是否为空
	if (!pDataTableEntry)
	{
		return;
	}

	/*

	开始遍历驱动对象链表

	*/

	//得到链表地址
	pList = pDataTableEntry->InLoadOrderLinks.Flink;

	//判断是否等于头部
	while (pList != &pDataTableEntry->InLoadOrderLinks)
	{
		pTempDataTableEntry = (LDR_DATA_TABLE_ENTRY*)pList;



		DbgPrint("驱动名称  ：%wZ , 模块地址：0x%x", &pTempDataTableEntry->FullDllName, &pTempDataTableEntry->EntryPoint);

		pList = pList->Flink;
	}
}
/*
833b62e0 8bff            mov     edi,edi
833b62e2 55              push    ebp
833b62e3 8bec            mov     ebp,esp
833b62e5 53              push    ebx
833b62e6 ff2510803b83    jmp     dword ptr [KMDFDriver1!p_KiAttachProcess (833b8010)]
*/
void __declspec(naked) My_KiAttachProcess()
{
	_asm {
		mov     edi, edi
		push    ebp
		mov     ebp, esp
		push    ebx
		jmp		p_KiAttachProcess
	}
}


void anti_hook_KiAttachProcess_method1()
{
	DbgPrint("anti_hook_KiAttachProcess_method1 worded");
	PageProOff();
	//DWORD32 shift = (ULONG)My_KiAttachProcess - 0x83e72067 - 5;
	//memcpy(0x83e72068, &shift, 4);
	if (*(char*)0x83ecd8d3 != 0x8b) {
		memcpy(0x83ecd8d3, code, 5);
	}
	PageProOn();
	KeSetTimer(&Timer, DueTime, &DPC);
}
void anti_hook_KiAttachProcess_method2()
{
	/*
	eb KiAttachProcess 8b
		eb KiAttachProcess + 1 ff
		eb KiAttachProcess + 2 55
		eb KiAttachProcess + 3 8b
		eb KiAttachProcess + 4 ec
		eb KiAttachProcess + 5 53
	*/
}
void SetKiAttachProcess() {
	DueTime.QuadPart = -10000 * 100;
	KeInitializeTimer(&Timer);
	KeInitializeDpc(&DPC, &anti_hook_KiAttachProcess_method1, NULL);
	KeSetTimer(&Timer, DueTime, &DPC);
}
VOID SetValidAccessMaskDpc() {
	DbgPrint("SetValidAccessMask worded");
	PageProOff();
	*ValidAccessMaskAdr = 0x1f000f;
	PageProOn();
	KeSetTimer(&TimerObject, NextTime, &DpcObject);
}
void monitor_TesSafe_Dpc()
{
	search_kernel_module_and_hide_template();
	if (flag = TRUE)
		return;
		KeSetTimer(&Timer, DueTime, &DPC);
}
void Set_Monitor_TesSafe()
{
	DueTime.QuadPart = -10000 * 100;
	KeInitializeTimer(&Timer);
	KeInitializeDpc(&DPC, &monitor_TesSafe_Dpc, NULL);
	KeSetTimer(&Timer, DueTime, &DPC);
}
VOID SetValidAccessMask()
{
	NextTime.QuadPart = -100000 * 100;
	KeInitializeTimer(&TimerObject);
	KeInitializeDpc(&DpcObject, &SetValidAccessMaskDpc, NULL);
	KeSetTimer(&TimerObject, NextTime, &DpcObject);
}

void anti_debug_port() {
	//ring3措施，比如PEB中BeingDebugged交给OD插件来处理
	/*
	加载TesSafe后 !process 0 0     ed eax+4 0xa0  将debugport移到createtime的地方
	TesSafe 基地址 0x98016000
	PROCESS 8771c560
	ba w4 8771c560+ec
9f22b512 a1745c269f      mov     eax,dword ptr ds:[9F265C74h]
9f22b517 8b4004          mov     eax,dword ptr [eax+4]
9f22b51a 0301            add     eax,dword ptr [ecx]
9f22b51c 56              push    esi
9f22b51d 33f6            xor     esi,esi
9f22b51f 8730            xchg    esi,dword ptr [eax]
9f22b521 8d91b9000000    lea     edx,[ecx+0B9h]
9f22b527 8b02            mov     eax,dword ptr [edx]
9f22b529 a802            test    al,2
9f22b52b 750b            jne     9f22b538
9f22b52d 85f6            test    esi,esi
9f22b52f 7407            je      9f22b538
9f22b531 8b39            mov     edi,dword ptr [ecx]
9f22b533 83c802          or      eax,2

//好像就一处清0的地方 把他给nop掉 有没有CRC另说！！
用windbg手动操作
eb 9f22b51f 90
eb 9f22b520 90

bp DbgkpSetProcessDebugObject
	*/
}

void anti_DbgBreakPoint()
{
	/*用pchunter恢复*/
}
