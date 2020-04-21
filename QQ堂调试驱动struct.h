#pragma once
#include<ntifs.h>
#include<ntdef.h>
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        struct
        {
            ULONG TimeDateStamp;
        };

        struct
        {
            PVOID LoadedImports;
        };
    };
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
/*
mov eax, dword ptr fs:[0h]//SEH结构化异常处理地址

mov eax, dword ptr fs:[18h]//TEB线程环境块

mov eax, dword ptr fs:[20h]//ClientId 客户端ID结构

kd> u nt!NtDebugActiveProcess
nt!NtDebugActiveProcess:
840f9b36 8bff            mov     edi,edi
840f9b38 55              push    ebp
840f9b39 8bec            mov     ebp,esp
840f9b3b 83ec10          sub     esp,10h
840f9b3e 64a124010000    mov     eax,dword ptr fs:[00000124h]

kd> u kiAttachProcess
nt!KiAttachProcess:
83ecd8d3 8bff            mov     edi,edi
83ecd8d5 55              push    ebp
83ecd8d6 8bec            mov     ebp,esp
83ecd8d8 53              push    ebx
83ecd8d9 8b5d08          mov     ebx,dword ptr [ebp+8]

kd> u kiAttachProcess
nt!KiAttachProcess:
83ecd8d3 68bc6123a0      push    0A02361BCh
83ecd8d8 c3              ret
nt!KeAttachProcess+0x7e:
83e72067 e8744254ff      call    KMDFDriver1!My_KiAttachProcess (833b62e0)
bp nt!NtDebugActiveProcess

kd> dt _OBJECT_TYPE 855d3668
nt!_OBJECT_TYPE
   +0x000 TypeList         : _LIST_ENTRY [ 0x855d3668 - 0x855d3668 ]
   +0x008 Name             : _UNICODE_STRING "DebugObject"
   +0x010 DefaultObject    : (null)
   +0x014 Index            : 0xb ''
   +0x018 TotalNumberOfObjects : 0
   +0x01c TotalNumberOfHandles : 0
   +0x020 HighWaterNumberOfObjects : 0
   +0x024 HighWaterNumberOfHandles : 0
   +0x028 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x078 TypeLock         : _EX_PUSH_LOCK
   +0x07c Key              : 0x75626544
   +0x080 CallbackList     : _LIST_ENTRY [ 0x855d36e8 - 0x855d36e8 ]
   kd> dx -id 0,0,855d39e8 -r1 (*((ntkrpamp!_OBJECT_TYPE_INITIALIZER *)0x855d3690))
(*((ntkrpamp!_OBJECT_TYPE_INITIALIZER *)0x855d3690))                 [Type: _OBJECT_TYPE_INITIALIZER]
    [+0x000] Length           : 0x50 [Type: unsigned short]
    [+0x002] ObjectTypeFlags  : 0x8 [Type: unsigned char]
    [+0x002 ( 0: 0)] CaseInsensitive  : 0x0 [Type: unsigned char]
    [+0x002 ( 1: 1)] UnnamedObjectsOnly : 0x0 [Type: unsigned char]
    [+0x002 ( 2: 2)] UseDefaultObject : 0x0 [Type: unsigned char]
    [+0x002 ( 3: 3)] SecurityRequired : 0x1 [Type: unsigned char]
    [+0x002 ( 4: 4)] MaintainHandleCount : 0x0 [Type: unsigned char]
    [+0x002 ( 5: 5)] MaintainTypeList : 0x0 [Type: unsigned char]
    [+0x002 ( 6: 6)] SupportsObjectCallbacks : 0x0 [Type: unsigned char]
    [+0x004] ObjectTypeCode   : 0x0 [Type: unsigned long]
    [+0x008] InvalidAttributes : 0x0 [Type: unsigned long]
    [+0x00c] GenericMapping   [Type: _GENERIC_MAPPING]
    [+0x01c] ValidAccessMask  : 0x1f000f [Type: unsigned long]
    [+0x020] RetainAccess     : 0x0 [Type: unsigned long]
    [+0x024] PoolType         : NonPagedPool (0) [Type: _POOL_TYPE]
    [+0x028] DefaultPagedPoolCharge : 0x0 [Type: unsigned long]
    [+0x02c] DefaultNonPagedPoolCharge : 0x30 [Type: unsigned long]
    [+0x030] DumpProcedure    : 0x0 [Type: void (*)(void *,_OBJECT_DUMP_CONTROL *)]
    [+0x034] OpenProcedure    : 0x0 [Type: long (*)(_OB_OPEN_REASON,char,_EPROCESS *,void *,unsigned long *,unsigned long)]
    [+0x038] CloseProcedure   : 0x840f898b [Type: void (*)(_EPROCESS *,void *,unsigned long,unsigned long)]
    [+0x03c] DeleteProcedure  : 0x840c887e [Type: void (*)(void *)]
    [+0x040] ParseProcedure   : 0x0 [Type: long (*)(void *,void *,_ACCESS_STATE *,char,unsigned long,_UNICODE_STRING *,_UNICODE_STRING *,void *,_SECURITY_QUALITY_OF_SERVICE *,void * *)]
    [+0x044] SecurityProcedure : 0x840b05b6 [Type: long (*)(void *,_SECURITY_OPERATION_CODE,unsigned long *,void *,unsigned long *,void * *,_POOL_TYPE,_GENERIC_MAPPING *,char)]
    [+0x048] QueryNameProcedure : 0x0 [Type: long (*)(void *,unsigned char,_OBJECT_NAME_INFORMATION *,unsigned long,unsigned long *,char)]
    [+0x04c] OkayToCloseProcedure : 0x0 [Type: unsigned char (*)(_EPROCESS *,void *,void *,char)]
    
    DebugPort是Debug_Object的指针

    NtDebugActiveProcess
    nt!DbgkpSetProcessDebugObject
    u DbgkpQueueMessage
    u DbgkpSetProcessDebugObject l20
    u DbgkpPostFakeProcessCreateMessages
    nt!NtDebugActiveProcess+0xaa:


840f9bc5 6a00            push    0
840f9bc7 8d45f8          lea     eax,[ebp-8]
840f9bca 50              push    eax
840f9bcb ff75f4          push    dword ptr [ebp-0Ch]
840f9bce ff35ac2df883    push    dword ptr [nt!DbgkDebugObjectType (83f82dac)] 调试对象类型的全局指针
840f9bd4 6a02            push    2
840f9bd6 ff750c          push    dword ptr [ebp+0Ch]
840f9bd9 e83632f7ff      call    nt!ObReferenceObjectByHandle (8406ce14)   eax为0xC0000022L
840f9bde 8bf8            mov     edi,eax
840f9be0 85ff            test    edi,edi
840f9be2 7c75            jl      nt!NtDebugActiveProcess+0x123 (840f9c59)
nt!NtDebugActiveProcess+0x123:
840f9c59 8bce            mov     ecx,esi
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)

 push    dword ptr [nt!DbgkDebugObjectType (83f82dac)] 估计是这里的问题
 默认权限 0x1f000f
*/


/*
kd> dt _eprocess 86444030
nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x098 ProcessLock      : _EX_PUSH_LOCK
   +0x0a0 CreateTime       : _LARGE_INTEGER 0x01d613ff`661c8909
   +0x0a8 ExitTime         : _LARGE_INTEGER 0x0
   +0x0b0 RundownProtect   : _EX_RUNDOWN_REF
   +0x0b4 UniqueProcessId  : 0x00000af8 Void
   +0x0b8 ActiveProcessLinks : _LIST_ENTRY [ 0x83f8cf18 - 0x85698548 ]
   +0x0c0 ProcessQuotaUsage : [2] 0x10c4
   +0x0c8 ProcessQuotaPeak : [2] 0x1234
   +0x0d0 CommitCharge     : 0x150
   +0x0d4 QuotaBlock       : 0x873a4380 _EPROCESS_QUOTA_BLOCK
   +0x0d8 CpuQuotaBlock    : (null)
   +0x0dc PeakVirtualSize  : 0x4aef000
   +0x0e0 VirtualSize      : 0x4aeb000
   +0x0e4 SessionProcessLinks : _LIST_ENTRY [ 0x8d656010 - 0x86a0ed6c ]
   +0x0ec DebugPort        : (null)
   +0x0f0 ExceptionPortData : 0x87360048 Void
   +0x0f0 ExceptionPortValue : 0x87360048
   +0x0f0 ExceptionPortState : 0y000
   +0x0f4 ObjectTable      : 0x8396f618 _HANDLE_TABLE
   +0x0f8 Token            : _EX_FAST_REF
   +0x0fc WorkingSetPage   : 0x6b36
   +0x100 AddressCreationLock : _EX_PUSH_LOCK
   +0x104 RotateInProgress : (null)
   +0x108 ForkInProgress   : (null)
   +0x10c HardwareTrigger  : 0
   +0x110 PhysicalVadRoot  : 0x856ab568 _MM_AVL_TABLE
   +0x114 CloneRoot        : (null)
   +0x118 NumberOfPrivatePages : 0x11b
   +0x11c NumberOfLockedPages : 0
   +0x120 Win32Process     : 0xfd1c5e30 Void
   +0x124 Job              : (null)
   +0x128 SectionObject    : 0x960d39a8 Void
   +0x12c SectionBaseAddress : 0x00400000 Void
   +0x130 Cookie           : 0x3d679be1
   +0x134 Spare8           : 0
   +0x138 WorkingSetWatch  : (null)
   +0x13c Win32WindowStation : 0x00000040 Void
   +0x140 InheritedFromUniqueProcessId : 0x00000540 Void
   +0x144 LdtInformation   : (null)
   +0x148 VdmObjects       : (null)
   +0x14c ConsoleHostProcess : 0
   +0x150 DeviceMap        : 0x8b56ec48 Void
   +0x154 EtwDataSource    : (null)
   +0x158 FreeTebHint      : 0x7ffdc000 Void
   +0x160 PageDirectoryPte : _HARDWARE_PTE
   +0x160 Filler           : 0
   +0x168 Session          : 0x8d656000 Void
   +0x16c ImageFileName    : [15]  "Dbgview.exe"
   +0x17b PriorityClass    : 0x2 ''
   +0x17c JobLinks         : _LIST_ENTRY [ 0x0 - 0x0 ]
   +0x184 LockedPagesList  : (null)
   +0x188 ThreadListHead   : _LIST_ENTRY [ 0x864447b8 - 0x85681990 ]
   +0x190 SecurityPort     : (null)
   +0x194 PaeTop           : 0x868d7420 Void
   +0x198 ActiveThreads    : 3
   +0x19c ImagePathHash    : 0xacbb6a5
   +0x1a0 DefaultHardErrorProcessing : 1
   +0x1a4 LastThreadExitStatus : 0n0
   +0x1a8 Peb              : 0x7ffdf000 _PEB
   +0x1ac PrefetchTrace    : _EX_FAST_REF
   +0x1b0 ReadOperationCount : _LARGE_INTEGER 0x2
   +0x1b8 WriteOperationCount : _LARGE_INTEGER 0x2
   +0x1c0 OtherOperationCount : _LARGE_INTEGER 0x12cd
   +0x1c8 ReadTransferCount : _LARGE_INTEGER 0x5f186
   +0x1d0 WriteTransferCount : _LARGE_INTEGER 0x3d00
   +0x1d8 OtherTransferCount : _LARGE_INTEGER 0x3df8
   +0x1e0 CommitChargeLimit : 0
   +0x1e4 CommitChargePeak : 0x152
   +0x1e8 AweInfo          : (null)
   +0x1ec SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x1f0 Vm               : _MMSUPPORT
   +0x25c MmProcessLinks   : _LIST_ENTRY [ 0x83f93370 - 0x856986ec ]
   +0x264 HighestUserAddress : 0x7fff0000 Void
   +0x268 ModifiedPageCount : 4
   +0x26c Flags2           : 0x2d000
   +0x26c JobNotReallyActive : 0y0
   +0x26c AccountingFolded : 0y0
   +0x26c NewProcessReported : 0y0
   +0x26c ExitProcessReported : 0y0
   +0x26c ReportCommitChanges : 0y0
   +0x26c LastReportMemory : 0y0
   +0x26c ReportPhysicalPageChanges : 0y0
   +0x26c HandleTableRundown : 0y0
   +0x26c NeedsHandleRundown : 0y0
   +0x26c RefTraceEnabled  : 0y0
   +0x26c NumaAware        : 0y0
   +0x26c ProtectedProcess : 0y0
   +0x26c DefaultPagePriority : 0y101
   +0x26c PrimaryTokenFrozen : 0y1
   +0x26c ProcessVerifierTarget : 0y0
   +0x26c StackRandomizationDisabled : 0y1
   +0x26c AffinityPermanent : 0y0
   +0x26c AffinityUpdateEnable : 0y0
   +0x26c PropagateNode    : 0y0
   +0x26c ExplicitAffinity : 0y0
   +0x270 Flags            : 0x144d0801
   +0x270 CreateReported   : 0y1
   +0x270 NoDebugInherit   : 0y0
   +0x270 ProcessExiting   : 0y0
   +0x270 ProcessDelete    : 0y0
   +0x270 Wow64SplitPages  : 0y0
   +0x270 VmDeleted        : 0y0
   +0x270 OutswapEnabled   : 0y0
   +0x270 Outswapped       : 0y0
   +0x270 ForkFailed       : 0y0
   +0x270 Wow64VaSpace4Gb  : 0y0
   +0x270 AddressSpaceInitialized : 0y10
   +0x270 SetTimerResolution : 0y0
   +0x270 BreakOnTermination : 0y0
   +0x270 DeprioritizeViews : 0y0
   +0x270 WriteWatch       : 0y0
   +0x270 ProcessInSession : 0y1
   +0x270 OverrideAddressSpace : 0y0
   +0x270 HasAddressSpace  : 0y1
   +0x270 LaunchPrefetched : 0y1
   +0x270 InjectInpageErrors : 0y0
   +0x270 VmTopDown        : 0y0
   +0x270 ImageNotifyDone  : 0y1
   +0x270 PdeUpdateNeeded  : 0y0
   +0x270 VdmAllowed       : 0y0
   +0x270 CrossSessionCreate : 0y0
   +0x270 ProcessInserted  : 0y1
   +0x270 DefaultIoPriority : 0y010
   +0x270 ProcessSelfDelete : 0y0
   +0x270 SetTimerResolutionLink : 0y0
   +0x274 ExitStatus       : 0n259
   +0x278 VadRoot          : _MM_AVL_TABLE
   +0x298 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x2a8 TimerResolutionLink : _LIST_ENTRY [ 0x0 - 0x0 ]
   +0x2b0 RequestedTimerResolution : 0
   +0x2b4 ActiveThreadsHighWatermark : 3
   +0x2b8 SmallestTimerResolution : 0
   +0x2bc TimerResolutionStackRecord : (null)


*/


/*
ba w4 debugport——addr

9e881521 8d91b9000000    lea     edx,[ecx+0B9h]


9fa2b512 a1745ca69f      mov     eax,dword ptr ds:[9FA65C74h]
kd> p
9fa2b517 8b4004          mov     eax,dword ptr [eax+4]
                        执行完eax 0xec  也就是debugport距离eprocess的偏移
kd> p
9fa2b51a 0301            add     eax,dword ptr [ecx]
                         ecx 指向Client.exe的eprocess的二级指针

                         Breakpoint 2 hit
9fa5951a 0301            add     eax,dword ptr [ecx]
kd>
Breakpoint 2 hit
9fa4c9d1 8bde            mov     ebx,esi //可能是检测的地方
kd> p
9fa4c9d3 f6c101          test    cl,1
kd> p
9fa4c9d6 750e            jne     9fa4c9e6

*/
