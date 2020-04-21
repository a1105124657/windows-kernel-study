/*
用IDA分析内核文件和NTDLL.DLL处理硬编码
*/

#include"driver.h"
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
	driver->DriverUnload = unloadDriver;
	driver_global = driver;
	kill_read_write_token();
	kill_double_machine();
	LDR_DATA_TABLE_ENTRY* p = search_kernel_module_and_hide(driver, L"kdcom.dll");
	if (p == NULL)
		DbgPrint("hide failed");
	//DbgPrint("%ws\n%p", p->BaseDllName.Buffer,p->DllBase);
	/*双机调试已通过 下面是ring3调试*/
	//先处理附加错误的问题
	anti_hook_KiAttachProcess_method2();
	/*r3能附加了，但是游戏会崩溃*/
	SetValidAccessMask();
	//处理DebugPort清0
	anti_debug_port();
	/*ring3*/
	anti_DbgBreakPoint();
	//还有一处检测线程（抛异常）给ban了 大概入口点倒数第二个位置
	/*
	异常部分代码
	001b:772d6068 b8ec000000      mov     eax,0ECh
	001b:772d606d ba0003fe7f      mov     edx,offset SharedUserData!SystemCallStub (7ffe0300)
kd> t
001b:772d6072 ff12            call    dword ptr [edx]
kd> t
001b:772d70b0 8bd4            mov     edx,esp
kd> t
001b:772d70b2 0f34            sysenter
kd> t
001b:772d6074 c21400          ret     14h
	kd> ba w 4[86e0b030+ec]
kd> g
Breakpoint 0 hit
9f42b521 8d91b9000000    lea     edx,[ecx+0B9h]
9f42b527 8b02            mov     eax,dword ptr [edx] 此时eax就是DebugPort地址
	*/
	return STATUS_SUCCESS;
}

