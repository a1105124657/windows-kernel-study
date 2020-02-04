#include"function.h"
__int64 EprocessOffset = 0x188;
__int64 PebOffset = 0x338;
typedef int WORD;
typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
	WORD Type;
	WORD CreatorBackTraceIndex;
	//PRTL_CRITICAL_SECTION CriticalSection;
	LIST_ENTRY ProcessLocksList;
	ULONG EntryCount;
	ULONG ContentionCount;
	ULONG Flags;
	WORD CreatorBackTraceIndexHigh;
	WORD SpareUSHORT;
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG;
typedef struct _RTL_CRITICAL_SECTION
{
	//PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;
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
typedef struct _PEB_FREE_BLOCK
{
	//PPEB_FREE_BLOCK Next;
	ULONG Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG ImageUsesLargePages : 1;
	ULONG IsProtectedProcess : 1;
	ULONG IsLegacyProcess : 1;
	ULONG IsImageDynamicallyRelocated : 1;
	ULONG SpareBits : 4;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	//PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	ULONG ProcessInJob : 1;
	ULONG ProcessInitializing : 1;
	ULONG ReservedBits0 : 30;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG SpareUlong;
	//PPEB_FREE_BLOCK FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	VOID** ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[34];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	//_ACTIVATION_CONTEXT_DATA* ActivationContextData;
	//_ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	//_ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
	//_ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	//_FLS_CALLBACK_INFO* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
} PEB, * PPEB;

//+0x188 ActiveProcessLinks 
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
	PUNICODE_STRING* pName2 = (PUNICODE_STRING*)((ULONG64)pProcess + 0x390);
	PWCHAR pBuffer = (PWCHAR)((ULONG64)(*pName2) + 8);
	WCHAR* buffer = L"\\Device\\HarddiskVolume1\\Windows\\System32\\csrss.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	RtlCopyMemory(pBuffer, buffer, 178);
	WPONx64(irql);
}
//原字符串，要替换的字符串，替换用的字符串
void FindStringAndChange(PEPROCESS pProcess,WCHAR* string, WCHAR* object)
{
	//object为"cheatengine-x8.exe","csrss.exe\0\0\0\0\0\0\0\0\0",
	WCHAR* source = L"csrss.exe\0\0\0\0\0\0\0\0\0";
	WCHAR* pos = wcsstr(string, object);
	int strLenth = judgeStringLen(object);
	WriteProcessMemory(pProcess, pos,(PVOID)source,strLenth);
}
void ChangePath(PEPROCESS pProcess)
{
	KAPC_STATE apc;
	//PEB-->ProcessParameters-->ImagePathName
	//PEB-->ProcessParameters-->CommandLine
	//PEB->ProcessParameters-->WindowTitle
	WCHAR* object = L"cheatengine-x8.exe";
	PPEB pPeb = (PPEB)*(ULONG64*)((ULONG64)pProcess + PebOffset); // x7fffxxxx
	//进入用户地址空间
	//DbgPrint("%p", pPeb);
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters = (ULONG64)pPeb + 0x20;
	DbgPrint("%p", pProcessParameters);
	PVOID64 p = (PVOID64)((ULONG64)(*pProcessParameters) + 0x60 + 0x10);
	//Memory mem = ReadProcessMemory(pProcess, p, 8);
	//DbgPrint("%p", mem.pMemory);
	//WCHAR* buffer_commandline = *(WCHAR*)((ULONG64)(*pProcessParameters) + 0x60 + 0x10);
	//DbgPrint("%p", buffer_commandline);
	//KeStackAttachProcess(pProcess, &apc);
	//ReadProcessMemory(pProcess, buffer_commandline, 10);
	//WCHAR* buffer_imagepathname = (pProcessParameters->ImagePathName).Buffer;
	//WCHAR* buffer_windowstitle = (pProcessParameters->WindowTitle).Buffer;
	//FindStringAndChange(pProcess, buffer_commandline, object);
	//FindStringAndChange(pProcess, buffer_imagepathname, object);
	//FindStringAndChange(pProcess, buffer_windowstitle, object);
	//DbgPrint("%p", buffer_imagepathname);
	//DbgPrint("%p", buffer_windowstitle);
}
int judgeStringLen(WCHAR* string)
{
	int i, lenth;
	i = lenth = 0;
	while (*(string + i))
	{
		lenth++;
		i++;
	}
	return 2 * (lenth + 1);
}



/*
Memory ReadProcessMemory(PEPROCESS pProcess, PVOID addr, INT lenth)
{
	KAPC_STATE apc;
	PVOID pbuffer = NULL;
	Memory mem;
	int i = 0;
	KeStackAttachProcess(pProcess, &apc);
	__try
	{
		ProbeForRead(addr, lenth, 1);
		pbuffer = ExAllocatePoolWithTag(NonPagedPool, lenth, 'tag1');
		if (!pbuffer)
		{
			DbgPrint("内存分配失败");
			mem.lenth = 0;
			mem.pMemory = NULL;
			return mem;
		}
		RtlCopyMemory(pbuffer, addr, lenth);
		while (i++ < lenth)
		{
			DbgPrint("%x", *((CHAR*)pbuffer + i - 1));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("读内存失败......");
	}
	KeUnstackDetachProcess (&apc);
	mem.lenth = lenth;
	mem.pMemory = pbuffer;
	return mem;
}
NTSTATUS WriteProcessMemory(PEPROCESS pProcess,PVOID addr,PVOID buffer,INT lenth)
{
}
*/
