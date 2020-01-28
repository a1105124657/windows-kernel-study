#include "driver.h"
void DriverUnLoad(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("驱动成功被卸载...OK-----------"));
}


//驱动入口函数
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	KdPrint(("驱动加载成功...OK-----------"));

	//转移 KdPitchDebugger = 1 与 KdDebuggerEnabled = 0
	MoveVariable_Win7();

	//转移 KiDebugRoutine 指向 KdpTrap
	//MoveKiDebugRoutine_Win7();

	//HOOK KiDebugRoutine 过蓝屏
	ChangeKiDebugRoutineAddr();




	DriverObject->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}
