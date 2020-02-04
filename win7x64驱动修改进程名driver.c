#include "driver.h"
#include"function.h"
void DriverUnLoad(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("驱动成功被卸载"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = DriverUnLoad;
	//cheatengine-x86_64.exe   截取15个字节 cheatengine-x8
	PEPROCESS pProcess = EnumProcess("cheatengine-x8");
	if ((pProcess) == (unsigned long long*)-1)
	{
		DbgPrint("error:没找到进程......");
		return STATUS_UNSUCCESSFUL;
	}
	ChangePath(pProcess);
	//ChangeProcessName(pProcess);
	return STATUS_SUCCESS;
}
