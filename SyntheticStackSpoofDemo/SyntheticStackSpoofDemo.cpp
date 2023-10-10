#include <Windows.h>

/*
         STACK CALCULATION & SPOOFING
*/

typedef struct _FRAME_METADATA {
    LPCWSTR         DllPath;
    PVOID           ReturnAddress;
    DWORD           FunctionOffset;
    DWORD           TotalStackSize;
    DWORD           CountOfCodes;
    BOOL            SetsFramePointer;
    BOOL            PushRbp;
    BOOL            PushRbpIndex;
} FRAME_METADATA, * PFRAME_METADATA;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE        CodeOffset;
        BYTE        UnwindOp : 4;
        BYTE        OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE            Version : 3;
    BYTE            Flags : 5;
    BYTE            SizeOfProlog;
    BYTE            CountOfCodes;
    BYTE            FrameRegister : 4;
    BYTE            FrameOffset : 4;
    UNWIND_CODE     UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;

typedef DWORD64 QWORD;

#pragma pack(push, 1) // Tightly packing the structure
typedef struct _NONVOL_REG_CTX {                        // (relative to start of PRM)
    QWORD           RBX;                                // 0x48 - 0x4F
    QWORD           RDI;                                // 0x50 - 0x57
    QWORD           RSI;                                // 0x58 - 0x5F
    QWORD           R12;                                // 0x60 - 0x67
    QWORD           R13;                                // 0x68 - 0x6F
    QWORD           R14;                                // 0x70 - 0x77
    QWORD           R15;                                // 0x78 - 0x7F
} NONVOL_REG_CTX, * PNONVOL_REG_CTX;

typedef struct _PRM {
    PVOID           FixupAddress;                       // 0x00 - 0x07
    PVOID           GadgetAddress;                      // 0x08 - 0x0F
    PVOID           OriginalReturnAddress;              // 0x10 - 0x17
    PVOID           BaseThreadInitFrameSize;            // 0x18 - 0x1F
    PVOID           BaseThreadInitReturnAddress;        // 0x20 - 0x27
    PVOID           RtlUserThreadStartFrameSize;        // 0x28 - 0x2F
    PVOID           RtlUserThreadStartReturnAddress;    // 0x30 - 0x37
    PVOID           GadgetFrameSize;                    // 0x38 - 0x3F
    PVOID           SystemCallNumber;                   // 0x40 - 0x47
    NONVOL_REG_CTX  NonvolRegisters;                    // 0x48 - 0x7F
} PRM, * PPRM;
#pragma pack(pop) // Restore the original packing

#define MAX_STACK_SIZE  12000
#define RBP_OP_INFO     0x5

DWORD GetFrameSize(PRUNTIME_FUNCTION RuntimeFunction, DWORD64 ImageBase, PFRAME_METADATA FrameMetadata)
{
    PUNWIND_INFO    UnwindInfo      = NULL;
    DWORD           UnwindOperation = NULL;
    DWORD           OperationInfo   = NULL;
    DWORD           Index           = NULL;
    DWORD           FrameOffset     = NULL;

    // 1. Sanity check
    if (!RuntimeFunction) {
        return ERROR_INVALID_PARAMETER;
    }

    // 2. Loop over unwind info codes and calculate frame size
    UnwindInfo = (PUNWIND_INFO)(RuntimeFunction->UnwindData + ImageBase);
    while (Index < UnwindInfo->CountOfCodes)
    {
        UnwindOperation = UnwindInfo->UnwindCode[Index].UnwindOp;
        OperationInfo = UnwindInfo->UnwindCode[Index].OpInfo;

        switch (UnwindOperation)
        {
        case UWOP_PUSH_NONVOL:
            FrameMetadata->TotalStackSize += 8; // Push takes 8 bytes
            if (RBP_OP_INFO == OperationInfo) {                          // Record when RBP is pushed
                FrameMetadata->PushRbp = TRUE;                           // as this important for UWOP_SET_FPREGS
                FrameMetadata->CountOfCodes = UnwindInfo->CountOfCodes;  //
                FrameMetadata->PushRbpIndex = Index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            Index++; // Doesn't contribute to frame size
            break;
        case UWOP_SAVE_NONVOL_FAR:
            Index++;
            break;
        case UWOP_ALLOC_SMALL:
            FrameMetadata->TotalStackSize += ((OperationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            Index++;
            FrameOffset = UnwindInfo->UnwindCode[Index].FrameOffset;
            if (OperationInfo == NULL)
            {
                FrameOffset *= 8;
            }
            else
            {
                Index++;
                FrameOffset += (UnwindInfo->UnwindCode[Index].FrameOffset << 16);
            }
            FrameMetadata->TotalStackSize += FrameOffset;
            break;
        case UWOP_SET_FPREG:
            FrameMetadata->SetsFramePointer = TRUE;
            break;
        default:
            return ERROR_NOT_SUPPORTED; // Unsuppored unwind opcode encountered
        }

        Index++;
    }

    // 3. If chained unwind information is present, then recursively parse it
    if (NULL != (UnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        Index = UnwindInfo->CountOfCodes;
        if (0 != (Index & 1))
        {
            Index++;
        }
        RuntimeFunction = (PRUNTIME_FUNCTION)(&UnwindInfo->UnwindCode[Index]);
        return GetFrameSize(RuntimeFunction, ImageBase, FrameMetadata);
    }

    // 4. Add return address size
    FrameMetadata->TotalStackSize += 8;
    return ERROR_SUCCESS;
}

DWORD GetFrameSizeByAddress(PVOID Address, PDWORD OutFrameSize)
{
    PRUNTIME_FUNCTION       RuntimeFunction = NULL;
    QWORD                   ImageBase       = NULL;
    PUNWIND_HISTORY_TABLE   HistoryTable    = NULL;
    FRAME_METADATA          FrameMetadata   = { NULL };

    // Sanity check return address
    if (!Address) return ERROR_INVALID_PARAMETER;

    // Locate RUNTIME_FUNCTION entry for the addresse
    RuntimeFunction = RtlLookupFunctionEntry(
        (QWORD)Address,
        &ImageBase,
        HistoryTable);
    if (NULL == RuntimeFunction)
    {
        return ERROR_NOT_FOUND;
    }

    return GetFrameSize(RuntimeFunction, ImageBase, &FrameMetadata);
}

extern "C" PVOID NTAPI Spoof(PVOID a, ...);

/* 
          GADGET FINDING
*/

int Memcmp(const void* Buffer1, const void* Buffer2, size_t Size)
{
    const unsigned char* p1 = (const unsigned char*)Buffer1;
    const unsigned char* p2 = (const unsigned char*)Buffer2;

    for (size_t i = 0; i < Size; i++) {
        if (p1[i] < p2[i]) {
            return -1;
        }
        else if (p1[i] > p2[i]) {
            return 1;
        }
    }

    return 0;
}

PIMAGE_SECTION_HEADER GetTextSectionHeader(HMODULE hModule) 
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(hModule);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(
        reinterpret_cast<PBYTE>(hModule) + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++Section) {
        if (Memcmp(Section->Name, ".text", 5) == 0) {
            return Section;
        }
    }

    return NULL;
}

PVOID FindByteSequence(PBYTE Start, SIZE_T Length, PBYTE Sequence, SIZE_T SequenceLength) 
{
    if (Sequence == NULL || SequenceLength == 0) {
        return NULL;
    }

    for (SIZE_T i = 0; i <= Length - SequenceLength; ++i) {
        bool Match = true;
        for (SIZE_T j = 0; j < SequenceLength; ++j) {
            if (Start[i + j] != Sequence[j]) {
                Match = false;
                break;
            }
        }
        if (Match) {
            return Start + i;
        }
    }

    return NULL;
}

PVOID FindGadget(PCSTR InModuleName, PBYTE Gadget, SIZE_T GadgetLength) 
{
    HMODULE ModBase = GetModuleHandleA(InModuleName);
    PIMAGE_SECTION_HEADER CodeHeader = GetTextSectionHeader(ModBase);

    PBYTE ImageBase = (PBYTE)ModBase;
    PBYTE TextSectionAddr = ImageBase + CodeHeader->VirtualAddress;

    return FindByteSequence(TextSectionAddr, CodeHeader->SizeOfRawData, Gadget, 2);
}

/*
            ENTRYPOINT
*/

INT Main()
{
    DWORD       Status          = NULL;
    DWORD       FrameSize       = NULL;
    PVOID       ReturnAddress   = NULL;
    PRM         Params          = { NULL };
    PRM         OrigParams      = { NULL };
    BYTE        Gadget[2]       = {0xff, 0x23};
    HMODULE     ModUser32       = LoadLibraryA("user32");
    HMODULE     ModKernel32     = GetModuleHandleA("kernel32");
    HMODULE     ModNtdll        = GetModuleHandleA("ntdll");

    if (!ModUser32 || !ModKernel32 || !ModNtdll) { return GetLastError(); }

    // Find JOP gadget `jmp rbx`
    Params.GadgetAddress = FindGadget("kernel32", Gadget, 2);
    if (Params.GadgetAddress == NULL) { return ERROR_NOT_FOUND; }
    Status = GetFrameSizeByAddress(Params.GadgetAddress, &FrameSize);
    if (Status != ERROR_SUCCESS) { return Status; }
    Params.GadgetFrameSize = (PVOID)FrameSize;

    // Get frame size and address of BaseThreadInitThunk
    ReturnAddress = (PBYTE)(GetProcAddress(ModKernel32, "BaseThreadInitThunk")) + 0x14;
    Params.BaseThreadInitReturnAddress = ReturnAddress;
    Status = GetFrameSizeByAddress(ReturnAddress, &FrameSize);
    if (Status != ERROR_SUCCESS) { return Status; }
    Params.BaseThreadInitFrameSize = (PVOID)FrameSize;

    // Get frame size and address of RtlUserThreadStart
    ReturnAddress = (PBYTE)(GetProcAddress(ModNtdll, "RtlUserThreadStart")) + 0x21;
    Params.RtlUserThreadStartReturnAddress = ReturnAddress;
    Status = GetFrameSizeByAddress(ReturnAddress, &FrameSize);
    if (Status != ERROR_SUCCESS) { return Status; }
    Params.RtlUserThreadStartFrameSize = (PVOID)FrameSize;
   
    // Test with some calls
    PVOID Alloc = Spoof(
        (PVOID)NULL, 
        (PVOID)1024, 
        (PVOID)(MEM_COMMIT | MEM_RESERVE),
        (PVOID)PAGE_READWRITE, 
            &Params, VirtualAlloc, 1
    );

    if (!Alloc) { return GetLastError(); }

    BOOL FreeOK = (BOOL)Spoof(
        Alloc,
        1024,
        MEM_RELEASE,
            &Params, VirtualFree, 0
    );

    if (!FreeOK) { return GetLastError(); }

    return ERROR_SUCCESS;
}