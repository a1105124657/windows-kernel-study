#include "driver.h"
#include"function.h"
void DriverUnLoad(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("驱动成功被卸载"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = DriverUnLoad;
	PEPROCESS pProcess = EnumProcess("cheatengine-x8");
	ChangeProcessName(pProcess);
	return STATUS_SUCCESS;
}
