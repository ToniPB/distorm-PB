; distorm_lib.pbi
; 
; diStorm3 - Powerful disassembler For X86/AMD64
; http://ragestorm.net/distorm/
; https://github.com/gdabah/distorm
;
; diStorm License =
;
;   distorm at gmail dot com
;   Copyright (C) 2003-2015 Gil Dabah
; 
;   This program is free software: you can redistribute it And/Or modify
;   it under the terms of the GNU General Public License As published by
;   the Free Software Foundation, either version 3 of the License, Or
;   (at your option) any later version.
; 
;   This program is distributed in the hope that it will be useful,
;   but WITHOUT ANY WARRANTY; without even the implied warranty of
;   MERCHANTABILITY Or FITNESS For A PARTICULAR PURPOSE.  See the
;   GNU General Public License For more details.
; 
;   You should have received a copy of the GNU General Public License
;   along With this program.  If Not, see <http://www.gnu.org/licenses/>
;


; Visual Studio Compile Settings =
;   
;   clib
;     ** General **
;       Target Name                 = distorm_$(PlatformShortName)
;       Whole Program Optimization  = No Whole Program Optimization
;     
;     ** Code Generation **
;       Enable C++ Exceptions       = No
;       Runtime Library             = Multi-threaded (/MT)
;       Buffer Security Check       = No (/GS-)
;

;
; Don't forget to set #DISTORM_LIB_PATH
;
; default is = #DISTORM_LIB_PATH = #PB_Compiler_FilePath + "..\distorm-master\"
;
;
; eg: #DISTORM_LIB_PATH = "C:\distorm\"
;

CompilerIf Defined(DISTORM_LIB_PBI, #PB_Constant) = 0
#DISTORM_LIB_PBI = 1

EnableExplicit

;- =====================================
;-        NAMING INFO
;- =====================================
;
; Macros have this prefix: DISTORM_M_
;
; Constants have this prefix: #DISTORM_
;
; Structures have this prefix: _DISTORM_
;
; Imported Function Names have no prefix
;
; Helper Functions have this prefix: DISTORM_
;

;- =====================================
;-        DATA TYPES
;- =====================================
;
; _OffsetType = .q (QUAD)
;
; OFFSET_INTEGER = .q (QUAD)
;
;- =====================================

; diStorm3 3.3
; 
; 
; distorm.pbi
; 
; diStorm3 - Powerful disassembler For X86/AMD64
; http://ragestorm.net/distorm/
; distorm at gmail dot com
; Copyright (C) 2003-2015 Gil Dabah
; 
; This program is free software: you can redistribute it And/Or modify
; it under the terms of the GNU General Public License As published by
; the Free Software Foundation, either version 3 of the License, Or
; (at your option) any later version.
; 
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY Or FITNESS For A PARTICULAR PURPOSE.  See the
; GNU General Public License For more details.
; 
; You should have received a copy of the GNU General Public License
; along With this program.  If Not, see <http://www.gnu.org/licenses/>


;  64 bit offsets support:
;  If the diStorm library you use was compiled With 64 bits offsets,
;  make sure you compile your own code With the following Macro set:
;  SUPPORT_64BIT_OFFSET
;  Otherwise comment it out, Or you will get a linker error of an unresolved symbol...
;  Turned on by Default!

; #DISTORM_SUPPORT_64BIT_OFFSET = 1


;  Helper Macros

; Get the ISC of the instruction, used with the definitions below.

Macro DISTORM_M_META_GET_ISC(__META__)
  (((__META__) >> 3) & $1f)
EndMacro

Macro DISTORM_M_META_SET_ISC(__DI__, __ISC__)
  (__DI__\meta | ((__ISC__) << 3))
EndMacro

; Get the flow control flags of the instruction, see 'features for decompose' below.
Macro DISTORM_M_META_GET_FC(__META__)
  ((__META__) & $7)
EndMacro

; Get the target address of a branching instruction. O_PC operand type.
Macro DISTORM_M_INSTRUCTION_GET_TARGET(__DI__)
  (__DI__\addr + __DI__\imm\addr + __DI__\size)
EndMacro

;  Get the target address of a RIP-relative memory indirection.
Macro DISTORM_M_INSTRUCTION_GET_RIP_TARGET(__DI__)
  (__DI__\addr + __DI__\disp + __DI__\size)
EndMacro

; Operand Size Or Adderss size are stored inside the flags:
; 00 - 16 bits
; 01 - 32 bits
; 10 - 64 bits
; 11 - reserved
; 
; If you call these set-macros more than once, you will have To clean the bits before doing so.


Macro DISTORM_M_FLAG_SET_OPSIZE(__DI__, __SIZE__)
  (__DI__\flags | (((__SIZE__) & 3) << 8))
EndMacro

Macro DISTORM_M_FLAG_SET_ADDRSIZE(__DI__, __SIZE__)
  (__DI__\flags | (((__SIZE__) & 3) << 10))
EndMacro

Macro DISTORM_M_FLAG_GET_OPSIZE(__FLAGS__)
  (((__FLAGS__) >> 8) & 3)
EndMacro

Macro DISTORM_M_FLAG_GET_ADDRSIZE(__FLAGS__)
  (((__FLAGS__) >> 10) & 3)
EndMacro

; To get the LOCK/REPNZ/REP prefixes.
Macro DISTORM_M_FLAG_GET_PREFIX(__FLAGS__)
  ((__FLAGS__) & 7)
EndMacro

; Indicates whether the instruction is privileged.
Macro DISTORM_M_FLAG_GET_PRIVILEGED(__FLAGS__)
  Bool(((__FLAGS__) & #DISTORM_FLAG_PRIVILEGED_INSTRUCTION) <> 0)
EndMacro

; Macros to extract segment registers from 'segment':

#DISTORM_SEGMENT_DEFAULT = $80


Macro DISTORM_M_SEGMENT_SET(__DI__, __SEG__)
  (__DI__\segment | __SEG__)
EndMacro

Macro DISTORM_M_SEGMENT_GET(__SEGMENT__, __VARIABLE__)
  If __SEGMENT__ = #DISTORM_R_NONE
    __VARIABLE__ = #DISTORM_R_NONE
  Else
    __VARIABLE__ = ((__SEGMENT__) & $7f)
  EndIf
EndMacro

Macro DISTORM_M_SEGMENT_IS_DEFAULT(__SEGMENT__)
  Bool( (__SEGMENT__ & #DISTORM_SEGMENT_DEFAULT) = #DISTORM_SEGMENT_DEFAULT )
EndMacro

;  Decodes modes of the disassembler, 16 bits or 32 bits or 64 bits for AMD64, x86-64.

#DISTORM_Decode16Bits = 0
#DISTORM_Decode32Bits = 1
#DISTORM_Decode64Bits = 2 

CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  
  Macro DISTORM_M_GET_DECODEMODE_PB()
    #DISTORM_Decode32Bits
  EndMacro
  
CompilerElse
  
  Macro DISTORM_M_GET_DECODEMODE_PB()
    #DISTORM_Decode64Bits
  EndMacro
  
CompilerEndIf




Structure _DISTORM_PB_Ascii_Array
  a.a[0]
EndStructure

Structure _DISTORM_CodeInfo Align #PB_Structure_AlignC
  codeOffset.q
  nextOffset.q                    ; nextOffset is OUT only.
  *code._DISTORM_PB_Ascii_Array   ; const uint8_t*
  codeLen.l                       ; Using signed integer makes it easier to detect an underflow.
  dt.l
  features.l
EndStructure

Structure _DISTORM_CodeInfo_array
  CodeInfo._DISTORM_CodeInfo[0]
EndStructure

; _OperandType

Enumeration
  #DISTORM_O_NONE
  #DISTORM_O_REG
  #DISTORM_O_IMM
  #DISTORM_O_IMM1
  #DISTORM_O_IMM2
  #DISTORM_O_DISP
  #DISTORM_O_SMEM
  #DISTORM_O_MEM
  #DISTORM_O_PC
  #DISTORM_O_PTR
EndEnumeration

Structure _DISTORM_Value_ptr Align #PB_Structure_AlignC
  seg.u
  ; Can be 16 or 32 bits, size is in ops[n].size.
  off.l
EndStructure

Structure _DISTORM_Value_ex Align #PB_Structure_AlignC
  i1.l
  i2.l
EndStructure
  
Structure _DISTORM_Value Align #PB_Structure_AlignC
  StructureUnion
    ; Used by O_IMM:
    sbyte.b
    byte.a
    sword.w
    word.u
    sdword.l
    dword.l
    sqword.q ; All immediates are SIGN-EXTENDED to 64 bits!
    qword.q
    
    ; Used by O_PC: (Use GET_TARGET_ADDR).
    addr.q ; It's a relative offset as for now.
    
    ; Used by O_PTR:
    ptr._DISTORM_Value_ptr
    
    ; Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only.
    ex._DISTORM_Value_ex
    
  EndStructureUnion
EndStructure

Structure _DISTORM_Operand Align #PB_Structure_AlignC
  ;   Type of operand:
  ; 		O_NONE: operand is To be ignored.
  ; 		O_REG: index holds Global register index.
  ; 		O_IMM: instruction.imm.
  ; 		O_IMM1: instruction.imm.ex.i1.
  ; 		O_IMM2: instruction.imm.ex.i2.
  ; 		O_DISP: memory dereference With displacement only, instruction.disp.
  ; 		O_SMEM: simple memory dereference With optional displacement (a single register memory dereference).
  ; 		O_MEM: complex memory dereference (optional fields: s/i/b/disp).
  ; 		O_PC: the relative address of a branch instruction (instruction.imm.addr).
  ; 		O_PTR: the absolute target address of a far branch instruction (instruction.imm.ptr.seg/off).
  
  type.a ; _OperandType
  
  ; Index of:
  ; 		O_REG: holds Global register index
  ; 		O_SMEM: holds the 'base' register. E.G: [ECX], [EBX+0x1234] are both in operand.index.
  ; 		O_MEM: holds the 'index' register. E.G: [EAX*4] is in operand.index.
  
  index.a
  
  ;  Size in bits of:
  ; 		O_REG: register
  ; 		O_IMM: instruction.imm
  ; 		O_IMM1: instruction.imm.ex.i1
  ; 		O_IMM2: instruction.imm.ex.i2
  ; 		O_DISP: instruction.disp
  ; 		O_SMEM: size of indirection.
  ; 		O_MEM: size of indirection.
  ; 		O_PC: size of the relative offset
  ; 		O_PTR: size of instruction.imm.ptr.off (16 Or 32)
  
  size.u
EndStructure

Structure _DISTORM_Operand_array
  Operand._DISTORM_Operand[0]
EndStructure


#DISTORM_OPCODE_ID_NONE = 0
; Instruction could not be disassembled.
#DISTORM_FLAG_NOT_DECODABLE = -1
; The instruction locks memory access.
#DISTORM_FLAG_LOCK = 1 << 0
; The instruction is prefixed with a REPNZ.
#DISTORM_FLAG_REPNZ = 1 << 1
; The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction.
#DISTORM_FLAG_REP = 1 << 2
; Indicates there is a hint taken for Jcc instructions only.
#DISTORM_FLAG_HINT_TAKEN = 1 << 3
; Indicates there is a hint non-taken for Jcc instructions only.
#DISTORM_FLAG_HINT_NOT_TAKEN = 1 << 4
; The Imm value is signed extended (E.G in 64 bit decoding mode, a 32 bit imm is usually sign extended into 64 bit imm).
#DISTORM_FLAG_IMM_SIGNED = 1 << 5
; The destination operand is writable.
#DISTORM_FLAG_DST_WR = 1 << 6
; The instruction uses RIP-relative indirection.
#DISTORM_FLAG_RIP_RELATIVE = 1 << 7

; See flag FLAG_GET_XXX macros above.

; The instruction is privileged and can only be used from Ring0.

#DISTORM_FLAG_PRIVILEGED_INSTRUCTION = 1 << 15

; No register was defined.
#DISTORM_R_NONE = -1

#DISTORM_REGS64_BASE = 0
#DISTORM_REGS32_BASE = 16
#DISTORM_REGS16_BASE = 32
#DISTORM_REGS8_BASE = 48
#DISTORM_REGS8_REX_BASE = 64
#DISTORM_SREGS_BASE = 68
#DISTORM_FPUREGS_BASE = 75
#DISTORM_MMXREGS_BASE = 83
#DISTORM_SSEREGS_BASE = 91
#DISTORM_AVXREGS_BASE = 107
#DISTORM_CREGS_BASE = 123
#DISTORM_DREGS_BASE = 132

#DISTORM_OPERANDS_NO = 4


Structure _DISTORM_DInst Align #PB_Structure_AlignC
  ; Used by ops[n].type == O_IMM/O_IMM1&O_IMM2/O_PTR/O_PC. Its size is ops[n].size.
  imm._DISTORM_Value
  
  ; Used by ops[n].type == O_SMEM/O_MEM/O_DISP. Its size is dispSize.
  disp.q
  
  ; Virtual address of first byte of instruction.
  addr.q
  
  ; General flags of instruction, holds prefixes and more, if FLAG_NOT_DECODABLE, instruction is invalid.
  flags.u
  
  ; Unused prefixes mask, for each bit that is set that prefix is not used (LSB is byte [addr + 0]).
  unusedPrefixesMask.u
  
  ; Mask of registers that were used in the operands, only used for quick look up, in order to know *some* operand uses that register class. 
  usedRegistersMask.l
  
  ; ID of opcode in the global opcode table. Use for mnemonic look up.
  opcode.u
  
  ; Up to four operands per instruction, ignored if ops[n].type == O_NONE.
  ops._DISTORM_Operand[#DISTORM_OPERANDS_NO]
  
  ; Size of the whole instruction in bytes.
  size.a
  
  ; Segment information of memory indirection, default segment, or overriden one, can be -1. Use SEGMENT macros.
  segment.a
  
  ; Used by ops[n].type == O_MEM. Base global register index (might be R_NONE), scale size (2/4/8), ignored for 0 or 1.
  base.a
  scale.a
  dispSize.a
  
  ; Meta defines the instruction set class, and the flow control flags. Use META macros.
  meta.a
  
  ; The CPU flags that the instruction operates upon.
  modifiedFlagsMask.u
  testedFlagsMask.u
  undefinedFlagsMask.u
EndStructure

Structure _DISTORM_DInst_array
  DInst._DISTORM_DInst[0]
EndStructure


; Static size of strings. Do not change this value. Keep Python wrapper in sync.
#DISTORM_MAX_TEXT_SIZE = 48


Structure _DISTORM_WString Align #PB_Structure_AlignC
  length.l
  p.a[#DISTORM_MAX_TEXT_SIZE] ;  p is a null terminated string.
EndStructure

Structure _DISTORM_WString_array
  WString._DISTORM_WString[0]
EndStructure

; Old decoded instruction Structure in text format.
; Used only For backward compatibility With diStorm64.
; This Structure holds all information the disassembler generates per instruction.

Structure _DISTORM_DecodedInst Align #PB_Structure_AlignC
  mnemonic._DISTORM_WString         ; Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc. 
  operands._DISTORM_WString         ; Operands of the decoded instruction, up to 3 operands, comma-seperated.
  instructionHex._DISTORM_WString   ; Hex dump - little endian, including prefixes.
  size.l                            ; Size of decoded instruction in bytes.
  offset.q                          ; Start offset of the decoded instruction.
EndStructure

Structure _DISTORM_DecodedInst_array
  DecodedInst._DISTORM_DecodedInst[0]
EndStructure

;  Register masks for quick look up, each mask indicates one of a register-class that is being used in some operand. 

#DISTORM_RM_AX = 1        ; AL, AH, AX, EAX, RAX
#DISTORM_RM_CX = 2        ; CL, CH, CX, ECX, RCX
#DISTORM_RM_DX = 4        ; DL, DH, DX, EDX, RDX
#DISTORM_RM_BX = 8        ; BL, BH, BX, EBX, RBX
#DISTORM_RM_SP = $10      ; SPL, SP, ESP, RSP 
#DISTORM_RM_BP = $20      ; BPL, BP, EBP, RBP
#DISTORM_RM_SI = $40      ; SIL, SI, ESI, RSI
#DISTORM_RM_DI = $80      ; DIL, DI, EDI, RDI
#DISTORM_RM_FPU = $100    ; ST(0) - ST(7)
#DISTORM_RM_MMX = $200    ; MM0 - MM7
#DISTORM_RM_SSE = $400    ; XMM0 - XMM15
#DISTORM_RM_AVX = $800    ; YMM0 - YMM15
#DISTORM_RM_CR = $1000    ; CR0, CR2, CR3, CR4, CR8
#DISTORM_RM_DR = $2000    ; DR0, DR1, DR2, DR3, DR6, DR7
#DISTORM_RM_R8 = $4000    ; R8B, R8W, R8D, R8
#DISTORM_RM_R9 = $8000    ; R9B, R9W, R9D, R9
#DISTORM_RM_R10 = $10000  ; R10B, R10W, R10D, R10
#DISTORM_RM_R11 = $20000  ; R11B, R11W, R11D, R11
#DISTORM_RM_R12 = $40000  ; R12B, R12W, R12D, R12
#DISTORM_RM_R13 = $80000  ; R13B, R13W, R13D, R13
#DISTORM_RM_R14 = $100000 ; R14B, R14W, R14D, R14
#DISTORM_RM_R15 = $200000 ; R15B, R15W, R15D, R15

; RIP should be checked using the 'flags' field And FLAG_RIP_RELATIVE.
; Segments should be checked using the segment macros.
; For now R8 - R15 are Not supported And non general purpose registers Map into same RM.

; CPU flags that instructions modify, test or undefine (are EFLAGS compatible!).
#DISTORM_D_CF = 1		  ; Carry 
#DISTORM_D_PF = 4		  ; Parity 
#DISTORM_D_AF = $10	  ; Auxiliary 
#DISTORM_D_ZF = $40	  ; Zero 
#DISTORM_D_SF = $80	  ; Sign 
#DISTORM_D_IF = $200	; Interrupt 
#DISTORM_D_DF = $400	; Direction 
#DISTORM_D_OF = $800	; Overflow 

; Instructions Set classes:
; If you want a better understanding of the available classes, look at disOps project, file: x86sets.py.

; Indicates the instruction belongs To the General Integer set.
#DISTORM_ISC_INTEGER = 1
; Indicates the instruction belongs to the 387 FPU set.
#DISTORM_ISC_FPU = 2
; Indicates the instruction belongs to the P6 set.
#DISTORM_ISC_P6 = 3
; Indicates the instruction belongs to the MMX set.
#DISTORM_ISC_MMX = 4
; Indicates the instruction belongs to the SSE set.
#DISTORM_ISC_SSE = 5
; Indicates the instruction belongs to the SSE2 set.
#DISTORM_ISC_SSE2 = 6
; Indicates the instruction belongs to the SSE3 set.
#DISTORM_ISC_SSE3 = 7
; Indicates the instruction belongs to the SSSE3 set.
#DISTORM_ISC_SSSE3 = 8
; Indicates the instruction belongs to the SSE4.1 set.
#DISTORM_ISC_SSE4_1 = 9
; Indicates the instruction belongs to the SSE4.2 set.
#DISTORM_ISC_SSE4_2 = 10
; Indicates the instruction belongs to the AMD's SSE4.A set.
#DISTORM_ISC_SSE4_A = 11
; Indicates the instruction belongs to the 3DNow! set.
#DISTORM_ISC_3DNOW = 12
; Indicates the instruction belongs to the 3DNow! Extensions set.
#DISTORM_ISC_3DNOWEXT = 13
; Indicates the instruction belongs to the VMX (Intel) set.
#DISTORM_ISC_VMX = 14
; Indicates the instruction belongs to the SVM (AMD) set.
#DISTORM_ISC_SVM = 15
; Indicates the instruction belongs to the AVX (Intel) set.
#DISTORM_ISC_AVX = 16
; Indicates the instruction belongs to the FMA (Intel) set.
#DISTORM_ISC_FMA = 17
; Indicates the instruction belongs to the AES/AVX (Intel) set.
#DISTORM_ISC_AES = 18
; Indicates the instruction belongs to the CLMUL (Intel) set.
#DISTORM_ISC_CLMUL = 19


; Features for decompose:

#DISTORM_DF_NONE = 0
; The decoder will limit addresses to a maximum of 16 bits.
#DISTORM_DF_MAXIMUM_ADDR16 = 1
; The decoder will limit addresses to a maximum of 32 bits.
#DISTORM_DF_MAXIMUM_ADDR32 = 2
; The decoder will return only flow control instructions (and filter the others internally).
#DISTORM_DF_RETURN_FC_ONLY = 4
; The decoder will stop and return to the caller when the instruction 'CALL' (near and far) was decoded.
#DISTORM_DF_STOP_ON_CALL = 8
; The decoder will stop and return to the caller when the instruction 'RET' (near and far) was decoded.
#DISTORM_DF_STOP_ON_RET = $10
; The decoder will stop and return to the caller when the instruction system-call/ret was decoded.
#DISTORM_DF_STOP_ON_SYS = $20
; The decoder will stop and return to the caller when any of the branch 'JMP', (near and far) instructions were decoded.
#DISTORM_DF_STOP_ON_UNC_BRANCH = $40
; The decoder will stop and return to the caller when any of the conditional branch instruction were decoded.
#DISTORM_DF_STOP_ON_CND_BRANCH = $80
; The decoder will stop and return to the caller when the instruction 'INT' (INT, INT1, INTO, INT 3) was decoded.
#DISTORM_DF_STOP_ON_INT = $100
; The decoder will stop and return to the caller when any of the 'CMOVxx' instruction was decoded.
#DISTORM_DF_STOP_ON_CMOV = $200
; The decoder will stop and return to the caller when any flow control instruction was decoded.
#DISTORM_DF_STOP_ON_FLOW_CONTROL = #DISTORM_DF_STOP_ON_CALL | #DISTORM_DF_STOP_ON_RET | #DISTORM_DF_STOP_ON_SYS | #DISTORM_DF_STOP_ON_UNC_BRANCH | #DISTORM_DF_STOP_ON_CND_BRANCH | #DISTORM_DF_STOP_ON_INT | #DISTORM_DF_STOP_ON_CMOV


; Indicates the instruction is Not a flow-control instruction.
#DISTORM_FC_NONE = 0
; Indicates the instruction is one of: CALL, CALL FAR.
#DISTORM_FC_CALL = 1
; Indicates the instruction is one of: RET, IRET, RETF.
#DISTORM_FC_RET = 2
; Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
#DISTORM_FC_SYS = 3
; Indicates the instruction is one of: JMP, JMP FAR. 
#DISTORM_FC_UNC_BRANCH = 4

; Indicates the instruction is one of:
; JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.

#DISTORM_FC_CND_BRANCH = 5
; Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
#DISTORM_FC_INT = 6
; Indicates the instruction is one of: CMOVxx.
#DISTORM_FC_CMOV = 7


; _DecodeResult
Enumeration
  #DISTORM_DECRES_NONE
  #DISTORM_DECRES_SUCCESS
  #DISTORM_DECRES_MEMORYERR
  #DISTORM_DECRES_INPUTERR
  #DISTORM_DECRES_FILTERED
EndEnumeration


;- =====================================
;-        LIB IMPORTS
;- =====================================

;  Return code of the decoding function.



CompilerIf Defined(DISTORM_LIB_PATH, #PB_Constant) = 0
#DISTORM_LIB_PATH = #PB_Compiler_FilePath + "..\distorm-master\"
CompilerEndIf

CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  #DISTORM_LIB_FULLPATH = #DISTORM_LIB_PATH + "distorm_x86.lib"
CompilerElse
  #DISTORM_LIB_FULLPATH = #DISTORM_LIB_PATH + "distorm_amd64.lib"
CompilerEndIf

; distorm_decode
;  * Input:
;  *         offset - Origin of the given code (virtual address that is), Not an offset in code.
;  *         code - Pointer To the code buffer To be disassembled.
;  *         length - Amount of bytes that should be decoded from the code buffer.
;  *         dt - Decoding mode, 16 bits (Decode16Bits), 32 bits (Decode32Bits) Or AMD64 (Decode64Bits).
;  *         result - Array of type _DecodeInst which will be used by this function in order To Return the disassembled instructions.
;  *         maxInstructions - The maximum number of entries in the result Array that you pass To this function, so it won't exceed its bound.
;  *         usedInstructionsCount - Number of the instruction that successfully were disassembled And written To the result Array.
;  * Output: usedInstructionsCount will hold the number of entries used in the result Array
;  *         And the result Array itself will be filled With the disassembled instructions.
;  * Return: DECRES_SUCCESS on success (no more To disassemble), DECRES_INPUTERR on input error (null code buffer, invalid decoding mode, etc...),
;  *         DECRES_MEMORYERR when there are Not enough entries To use in the result Array, BUT YOU STILL have To check For usedInstructionsCount!
;  * Side-Effects: Even If the Return code is DECRES_MEMORYERR, there might STILL be Data in the
;  *               Array you passed, this function will try To use As much entries As possible!
;  * Notes:  1)The minimal size of maxInstructions is 15.
;  *         2)You will have To synchronize the offset,code And length by yourself If you pass code fragments And Not a complete code block!

;  distorm_decompose
;  * There is lots of documentation about diStorm at https://code.google.com/p/distorm/wiki
;  *
;  * Please Read https://code.google.com/p/distorm/wiki/DecomposeInterface
;  *
;  * And also see https://code.google.com/p/distorm/wiki/TipsnTricks
CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  ImportC #DISTORM_LIB_FULLPATH
CompilerElse
  Import #DISTORM_LIB_FULLPATH
CompilerEndIf
  distorm_decompose64.l(*ci._DISTORM_CodeInfo, *result._DISTORM_DInst, maxInstructions.l, *usedInstructionsCount.LONG)
  
  distorm_decode64.l(codeOffset.q, *code, codeLen.l, dt.l, *result._DISTORM_DecodedInst, maxInstructions.l, *usedInstructionsCount.LONG)
  
  distorm_format64(*ci._DISTORM_CodeInfo, *di._DISTORM_DInst, *result._DISTORM_DecodedInst)
  
  ;  * distorm_version
  ;  * Input:
  ;  *        none
  ;  *
  ;  * Output: unsigned int - version of compiled library.

  distorm_version.l()
EndImport






;- =====================================
;- Mnemonics
;- =====================================

Structure _DISTORM_WMnemonic Align #PB_Structure_AlignC
  length.a
  p.a[1] ;  p is a null terminated string, which contains 'length' characters.
EndStructure

Structure _DISTORM_WMnemonic_array Align #PB_Structure_AlignC
  WMnemonic._DISTORM_WMnemonic[0]
EndStructure

Structure _DISTORM_WRegister Align #PB_Structure_AlignC
  length.l
  p.a[6] ; p is a null terminated string.
EndStructure

Structure _DISTORM_WRegister_array Align #PB_Structure_AlignC
  WRegister._DISTORM_WRegister[0]
EndStructure



CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  ImportC #DISTORM_LIB_FULLPATH
CompilerElse
  Import #DISTORM_LIB_FULLPATH
CompilerEndIf

  ; extern const unsigned char _MNEMONICS[];
  _MNEMONICS()
  ; extern const _WRegister _REGISTERS[];
  _REGISTERS()
EndImport


Macro DISTORM_M_GET_REGISTER_NAME(__R__)
  PeekS(@_REGISTERS() + __R__ * SizeOf(_DISTORM_WRegister) + OffsetOf(_DISTORM_WRegister\p), -1, #PB_Ascii)
EndMacro

;Macro DISTORM_M_GET_MNEMONIC_NAME(__M__)
  ;PeekS(@_MNEMONICS() + __M__ * SizeOf(_DISTORM_WMnemonic) + OffsetOf(_DISTORM_WMnemonic\p), -1, #PB_Ascii)
  
  ;PeekS(@_MNEMONICS() + __M__ * SizeOf(_DISTORM_WMnemonic) + OffsetOf(_DISTORM_WMnemonic\p), -1, #PB_Ascii)
;EndMacro



; _InstructionType

Enumeration
  #DISTORM_I_UNDEFINED = 0
  #DISTORM_I_AAA = 66
  #DISTORM_I_AAD = 389
  #DISTORM_I_AAM = 384
  #DISTORM_I_AAS = 76
  #DISTORM_I_ADC = 31
  #DISTORM_I_ADD = 11
  #DISTORM_I_ADDPD = 3110
  #DISTORM_I_ADDPS = 3103
  #DISTORM_I_ADDSD = 3124
  #DISTORM_I_ADDSS = 3117
  #DISTORM_I_ADDSUBPD = 6394
  #DISTORM_I_ADDSUBPS = 6404
  #DISTORM_I_AESDEC = 9209
  #DISTORM_I_AESDECLAST = 9226
  #DISTORM_I_AESENC = 9167
  #DISTORM_I_AESENCLAST = 9184
  #DISTORM_I_AESIMC = 9150
  #DISTORM_I_AESKEYGENASSIST = 9795
  #DISTORM_I_AND = 41
  #DISTORM_I_ANDNPD = 3021
  #DISTORM_I_ANDNPS = 3013
  #DISTORM_I_ANDPD = 2990
  #DISTORM_I_ANDPS = 2983
  #DISTORM_I_ARPL = 111
  #DISTORM_I_BLENDPD = 9372
  #DISTORM_I_BLENDPS = 9353
  #DISTORM_I_BLENDVPD = 7619
  #DISTORM_I_BLENDVPS = 7609
  #DISTORM_I_BOUND = 104
  #DISTORM_I_BSF = 4346
  #DISTORM_I_BSR = 4358
  #DISTORM_I_BSWAP = 960
  #DISTORM_I_BT = 872
  #DISTORM_I_BTC = 934
  #DISTORM_I_BTR = 912
  #DISTORM_I_BTS = 887
  #DISTORM_I_CALL = 456
  #DISTORM_I_CALL_FAR = 260
  #DISTORM_I_CBW = 228
  #DISTORM_I_CDQ = 250
  #DISTORM_I_CDQE = 239
  #DISTORM_I_CLC = 492
  #DISTORM_I_CLD = 512
  #DISTORM_I_CLFLUSH = 4329
  #DISTORM_I_CLGI = 1833
  #DISTORM_I_CLI = 502
  #DISTORM_I_CLTS = 541
  #DISTORM_I_CMC = 487
  #DISTORM_I_CMOVA = 694
  #DISTORM_I_CMOVAE = 663
  #DISTORM_I_CMOVB = 656
  #DISTORM_I_CMOVBE = 686
  #DISTORM_I_CMOVG = 754
  #DISTORM_I_CMOVGE = 738
  #DISTORM_I_CMOVL = 731
  #DISTORM_I_CMOVLE = 746
  #DISTORM_I_CMOVNO = 648
  #DISTORM_I_CMOVNP = 723
  #DISTORM_I_CMOVNS = 708
  #DISTORM_I_CMOVNZ = 678
  #DISTORM_I_CMOVO = 641
  #DISTORM_I_CMOVP = 716
  #DISTORM_I_CMOVS = 701
  #DISTORM_I_CMOVZ = 671
  #DISTORM_I_CMP = 71
  #DISTORM_I_CMPEQPD = 4449
  #DISTORM_I_CMPEQPS = 4370
  #DISTORM_I_CMPEQSD = 4607
  #DISTORM_I_CMPEQSS = 4528
  #DISTORM_I_CMPLEPD = 4467
  #DISTORM_I_CMPLEPS = 4388
  #DISTORM_I_CMPLESD = 4625
  #DISTORM_I_CMPLESS = 4546
  #DISTORM_I_CMPLTPD = 4458
  #DISTORM_I_CMPLTPS = 4379
  #DISTORM_I_CMPLTSD = 4616
  #DISTORM_I_CMPLTSS = 4537
  #DISTORM_I_CMPNEQPD = 4488
  #DISTORM_I_CMPNEQPS = 4409
  #DISTORM_I_CMPNEQSD = 4646
  #DISTORM_I_CMPNEQSS = 4567
  #DISTORM_I_CMPNLEPD = 4508
  #DISTORM_I_CMPNLEPS = 4429
  #DISTORM_I_CMPNLESD = 4666
  #DISTORM_I_CMPNLESS = 4587
  #DISTORM_I_CMPNLTPD = 4498
  #DISTORM_I_CMPNLTPS = 4419
  #DISTORM_I_CMPNLTSD = 4656
  #DISTORM_I_CMPNLTSS = 4577
  #DISTORM_I_CMPORDPD = 4518
  #DISTORM_I_CMPORDPS = 4439
  #DISTORM_I_CMPORDSD = 4676
  #DISTORM_I_CMPORDSS = 4597
  #DISTORM_I_CMPS = 301
  #DISTORM_I_CMPUNORDPD = 4476
  #DISTORM_I_CMPUNORDPS = 4397
  #DISTORM_I_CMPUNORDSD = 4634
  #DISTORM_I_CMPUNORDSS = 4555
  #DISTORM_I_CMPXCHG = 898
  #DISTORM_I_CMPXCHG16B = 6373
  #DISTORM_I_CMPXCHG8B = 6362
  #DISTORM_I_COMISD = 2779
  #DISTORM_I_COMISS = 2771
  #DISTORM_I_CPUID = 865
  #DISTORM_I_CQO = 255
  #DISTORM_I_CRC32 = 9258
  #DISTORM_I_CVTDQ2PD = 6787
  #DISTORM_I_CVTDQ2PS = 3307
  #DISTORM_I_CVTPD2DQ = 6797
  #DISTORM_I_CVTPD2PI = 2681
  #DISTORM_I_CVTPD2PS = 3233
  #DISTORM_I_CVTPH2PS = 4161
  #DISTORM_I_CVTPI2PD = 2495
  #DISTORM_I_CVTPI2PS = 2485
  #DISTORM_I_CVTPS2DQ = 3317
  #DISTORM_I_CVTPS2PD = 3223
  #DISTORM_I_CVTPS2PH = 4171
  #DISTORM_I_CVTPS2PI = 2671
  #DISTORM_I_CVTSD2SI = 2701
  #DISTORM_I_CVTSD2SS = 3253
  #DISTORM_I_CVTSI2SD = 2515
  #DISTORM_I_CVTSI2SS = 2505
  #DISTORM_I_CVTSS2SD = 3243
  #DISTORM_I_CVTSS2SI = 2691
  #DISTORM_I_CVTTPD2DQ = 6776
  #DISTORM_I_CVTTPD2PI = 2614
  #DISTORM_I_CVTTPS2DQ = 3327
  #DISTORM_I_CVTTPS2PI = 2603
  #DISTORM_I_CVTTSD2SI = 2636
  #DISTORM_I_CVTTSS2SI = 2625
  #DISTORM_I_CWD = 245
  #DISTORM_I_CWDE = 233
  #DISTORM_I_DAA = 46
  #DISTORM_I_DAS = 56
  #DISTORM_I_DEC = 86
  #DISTORM_I_DIV = 1630
  #DISTORM_I_DIVPD = 3499
  #DISTORM_I_DIVPS = 3492
  #DISTORM_I_DIVSD = 3513
  #DISTORM_I_DIVSS = 3506
  #DISTORM_I_DPPD = 9615
  #DISTORM_I_DPPS = 9602
  #DISTORM_I_EMMS = 4100
  #DISTORM_I_ENTER = 340
  #DISTORM_I_EXTRACTPS = 9480
  #DISTORM_I_EXTRQ = 4136
  #DISTORM_I_F2XM1 = 1176
  #DISTORM_I_FABS = 1107
  #DISTORM_I_FADD = 1007
  #DISTORM_I_FADDP = 1533
  #DISTORM_I_FBLD = 1585
  #DISTORM_I_FBSTP = 1591
  #DISTORM_I_FCHS = 1101
  #DISTORM_I_FCLEX = 7289
  #DISTORM_I_FCMOVB = 1360
  #DISTORM_I_FCMOVBE = 1376
  #DISTORM_I_FCMOVE = 1368
  #DISTORM_I_FCMOVNB = 1429
  #DISTORM_I_FCMOVNBE = 1447
  #DISTORM_I_FCMOVNE = 1438
  #DISTORM_I_FCMOVNU = 1457
  #DISTORM_I_FCMOVU = 1385
  #DISTORM_I_FCOM = 1019
  #DISTORM_I_FCOMI = 1496
  #DISTORM_I_FCOMIP = 1607
  #DISTORM_I_FCOMP = 1025
  #DISTORM_I_FCOMPP = 1547
  #DISTORM_I_FCOS = 1295
  #DISTORM_I_FDECSTP = 1222
  #DISTORM_I_FDIV = 1045
  #DISTORM_I_FDIVP = 1578
  #DISTORM_I_FDIVR = 1051
  #DISTORM_I_FDIVRP = 1570
  #DISTORM_I_FEDISI = 1472
  #DISTORM_I_FEMMS = 574
  #DISTORM_I_FENI = 1466
  #DISTORM_I_FFREE = 1511
  #DISTORM_I_FIADD = 1301
  #DISTORM_I_FICOM = 1315
  #DISTORM_I_FICOMP = 1322
  #DISTORM_I_FIDIV = 1345
  #DISTORM_I_FIDIVR = 1352
  #DISTORM_I_FILD = 1402
  #DISTORM_I_FIMUL = 1308
  #DISTORM_I_FINCSTP = 1231
  #DISTORM_I_FINIT = 7304
  #DISTORM_I_FIST = 1416
  #DISTORM_I_FISTP = 1422
  #DISTORM_I_FISTTP = 1408
  #DISTORM_I_FISUB = 1330
  #DISTORM_I_FISUBR = 1337
  #DISTORM_I_FLD = 1058
  #DISTORM_I_FLD1 = 1125
  #DISTORM_I_FLDCW = 1082
  #DISTORM_I_FLDENV = 1074
  #DISTORM_I_FLDL2E = 1139
  #DISTORM_I_FLDL2T = 1131
  #DISTORM_I_FLDLG2 = 1154
  #DISTORM_I_FLDLN2 = 1162
  #DISTORM_I_FLDPI = 1147
  #DISTORM_I_FLDZ = 1170
  #DISTORM_I_FMUL = 1013
  #DISTORM_I_FMULP = 1540
  #DISTORM_I_FNCLEX = 7281
  #DISTORM_I_FNINIT = 7296
  #DISTORM_I_FNOP = 1095
  #DISTORM_I_FNSAVE = 7311
  #DISTORM_I_FNSTCW = 7266
  #DISTORM_I_FNSTENV = 7249
  #DISTORM_I_FNSTSW = 7326
  #DISTORM_I_FPATAN = 1197
  #DISTORM_I_FPREM = 1240
  #DISTORM_I_FPREM1 = 1214
  #DISTORM_I_FPTAN = 1190
  #DISTORM_I_FRNDINT = 1272
  #DISTORM_I_FRSTOR = 1503
  #DISTORM_I_FSAVE = 7319
  #DISTORM_I_FSCALE = 1281
  #DISTORM_I_FSETPM = 1480
  #DISTORM_I_FSIN = 1289
  #DISTORM_I_FSINCOS = 1263
  #DISTORM_I_FSQRT = 1256
  #DISTORM_I_FST = 1063
  #DISTORM_I_FSTCW = 7274
  #DISTORM_I_FSTENV = 7258
  #DISTORM_I_FSTP = 1068
  #DISTORM_I_FSTSW = 7334
  #DISTORM_I_FSUB = 1032
  #DISTORM_I_FSUBP = 1563
  #DISTORM_I_FSUBR = 1038
  #DISTORM_I_FSUBRP = 1555
  #DISTORM_I_FTST = 1113
  #DISTORM_I_FUCOM = 1518
  #DISTORM_I_FUCOMI = 1488
  #DISTORM_I_FUCOMIP = 1598
  #DISTORM_I_FUCOMP = 1525
  #DISTORM_I_FUCOMPP = 1393
  #DISTORM_I_FXAM = 1119
  #DISTORM_I_FXCH = 1089
  #DISTORM_I_FXRSTOR = 9892
  #DISTORM_I_FXRSTOR64 = 9901
  #DISTORM_I_FXSAVE = 9864
  #DISTORM_I_FXSAVE64 = 9872
  #DISTORM_I_FXTRACT = 1205
  #DISTORM_I_FYL2X = 1183
  #DISTORM_I_FYL2XP1 = 1247
  #DISTORM_I_GETSEC = 633
  #DISTORM_I_HADDPD = 4181
  #DISTORM_I_HADDPS = 4189
  #DISTORM_I_HLT = 482
  #DISTORM_I_HSUBPD = 4215
  #DISTORM_I_HSUBPS = 4223
  #DISTORM_I_IDIV = 1635
  #DISTORM_I_IMUL = 117
  #DISTORM_I_IN = 447
  #DISTORM_I_INC = 81
  #DISTORM_I_INS = 123
  #DISTORM_I_INSERTPS = 9547
  #DISTORM_I_INSERTQ = 4143
  #DISTORM_I_INT = 367
  #DISTORM_I_INT_3 = 360
  #DISTORM_I_INT1 = 476
  #DISTORM_I_INTO = 372
  #DISTORM_I_INVD = 555
  #DISTORM_I_INVEPT = 8284
  #DISTORM_I_INVLPG = 1711
  #DISTORM_I_INVLPGA = 1847
  #DISTORM_I_INVPCID = 8301
  #DISTORM_I_INVVPID = 8292
  #DISTORM_I_IRET = 378
  #DISTORM_I_JA = 166
  #DISTORM_I_JAE = 147
  #DISTORM_I_JB = 143
  #DISTORM_I_JBE = 161
  #DISTORM_I_JCXZ = 427
  #DISTORM_I_JECXZ = 433
  #DISTORM_I_JG = 202
  #DISTORM_I_JGE = 192
  #DISTORM_I_JL = 188
  #DISTORM_I_JLE = 197
  #DISTORM_I_JMP = 462
  #DISTORM_I_JMP_FAR = 467
  #DISTORM_I_JNO = 138
  #DISTORM_I_JNP = 183
  #DISTORM_I_JNS = 174
  #DISTORM_I_JNZ = 156
  #DISTORM_I_JO = 134
  #DISTORM_I_JP = 179
  #DISTORM_I_JRCXZ = 440
  #DISTORM_I_JS = 170
  #DISTORM_I_JZ = 152
  #DISTORM_I_LAHF = 289
  #DISTORM_I_LAR = 522
  #DISTORM_I_LDDQU = 6994
  #DISTORM_I_LDMXCSR = 9922
  #DISTORM_I_LDS = 335
  #DISTORM_I_LEA = 223
  #DISTORM_I_LEAVE = 347
  #DISTORM_I_LES = 330
  #DISTORM_I_LFENCE = 4265
  #DISTORM_I_LFS = 917
  #DISTORM_I_LGDT = 1687
  #DISTORM_I_LGS = 922
  #DISTORM_I_LIDT = 1693
  #DISTORM_I_LLDT = 1652
  #DISTORM_I_LMSW = 1705
  #DISTORM_I_LODS = 313
  #DISTORM_I_LOOP = 421
  #DISTORM_I_LOOPNZ = 406
  #DISTORM_I_LOOPZ = 414
  #DISTORM_I_LSL = 527
  #DISTORM_I_LSS = 907
  #DISTORM_I_LTR = 1658
  #DISTORM_I_LZCNT = 4363
  #DISTORM_I_MASKMOVDQU = 7119
  #DISTORM_I_MASKMOVQ = 7109
  #DISTORM_I_MAXPD = 3559
  #DISTORM_I_MAXPS = 3552
  #DISTORM_I_MAXSD = 3573
  #DISTORM_I_MAXSS = 3566
  #DISTORM_I_MFENCE = 4291
  #DISTORM_I_MINPD = 3439
  #DISTORM_I_MINPS = 3432
  #DISTORM_I_MINSD = 3453
  #DISTORM_I_MINSS = 3446
  #DISTORM_I_MONITOR = 1755
  #DISTORM_I_MOV = 218
  #DISTORM_I_MOVAPD = 2459
  #DISTORM_I_MOVAPS = 2451
  #DISTORM_I_MOVBE = 9251
  #DISTORM_I_MOVD = 3920
  #DISTORM_I_MOVDDUP = 2186
  #DISTORM_I_MOVDQ2Q = 6522
  #DISTORM_I_MOVDQA = 3946
  #DISTORM_I_MOVDQU = 3954
  #DISTORM_I_MOVHLPS = 2151
  #DISTORM_I_MOVHPD = 2345
  #DISTORM_I_MOVHPS = 2337
  #DISTORM_I_MOVLHPS = 2328
  #DISTORM_I_MOVLPD = 2168
  #DISTORM_I_MOVLPS = 2160
  #DISTORM_I_MOVMSKPD = 2815
  #DISTORM_I_MOVMSKPS = 2805
  #DISTORM_I_MOVNTDQ = 6849
  #DISTORM_I_MOVNTDQA = 7895
  #DISTORM_I_MOVNTI = 952
  #DISTORM_I_MOVNTPD = 2556
  #DISTORM_I_MOVNTPS = 2547
  #DISTORM_I_MOVNTQ = 6841
  #DISTORM_I_MOVNTSD = 2574
  #DISTORM_I_MOVNTSS = 2565
  #DISTORM_I_MOVQ = 3926
  #DISTORM_I_MOVQ2DQ = 6513
  #DISTORM_I_MOVS = 295
  #DISTORM_I_MOVSD = 2110
  #DISTORM_I_MOVSHDUP = 2353
  #DISTORM_I_MOVSLDUP = 2176
  #DISTORM_I_MOVSS = 2103
  #DISTORM_I_MOVSX = 939
  #DISTORM_I_MOVSXD = 10005
  #DISTORM_I_MOVUPD = 2095
  #DISTORM_I_MOVUPS = 2087
  #DISTORM_I_MOVZX = 927
  #DISTORM_I_MPSADBW = 9628
  #DISTORM_I_MUL = 1625
  #DISTORM_I_MULPD = 3170
  #DISTORM_I_MULPS = 3163
  #DISTORM_I_MULSD = 3184
  #DISTORM_I_MULSS = 3177
  #DISTORM_I_MWAIT = 1764
  #DISTORM_I_NEG = 1620
  #DISTORM_I_NOP = 581
  #DISTORM_I_NOT = 1615
  #DISTORM_I_OR = 27
  #DISTORM_I_ORPD = 3053
  #DISTORM_I_ORPS = 3047
  #DISTORM_I_OUT = 451
  #DISTORM_I_OUTS = 128
  #DISTORM_I_PABSB = 7688
  #DISTORM_I_PABSD = 7718
  #DISTORM_I_PABSW = 7703
  #DISTORM_I_PACKSSDW = 3849
  #DISTORM_I_PACKSSWB = 3681
  #DISTORM_I_PACKUSDW = 7916
  #DISTORM_I_PACKUSWB = 3759
  #DISTORM_I_PADDB = 7204
  #DISTORM_I_PADDD = 7234
  #DISTORM_I_PADDQ = 6481
  #DISTORM_I_PADDSB = 6930
  #DISTORM_I_PADDSW = 6947
  #DISTORM_I_PADDUSB = 6620
  #DISTORM_I_PADDUSW = 6639
  #DISTORM_I_PADDW = 7219
  #DISTORM_I_PALIGNR = 9410
  #DISTORM_I_PAND = 6607
  #DISTORM_I_PANDN = 6665
  #DISTORM_I_PAUSE = 10013
  #DISTORM_I_PAVGB = 6680
  #DISTORM_I_PAVGUSB = 2078
  #DISTORM_I_PAVGW = 6725
  #DISTORM_I_PBLENDVB = 7599
  #DISTORM_I_PBLENDW = 9391
  #DISTORM_I_PCLMULQDQ = 9647
  #DISTORM_I_PCMPEQB = 4043
  #DISTORM_I_PCMPEQD = 4081
  #DISTORM_I_PCMPEQQ = 7876
  #DISTORM_I_PCMPEQW = 4062
  #DISTORM_I_PCMPESTRI = 9726
  #DISTORM_I_PCMPESTRM = 9703
  #DISTORM_I_PCMPGTB = 3702
  #DISTORM_I_PCMPGTD = 3740
  #DISTORM_I_PCMPGTQ = 8087
  #DISTORM_I_PCMPGTW = 3721
  #DISTORM_I_PCMPISTRI = 9772
  #DISTORM_I_PCMPISTRM = 9749
  #DISTORM_I_PEXTRB = 9429
  #DISTORM_I_PEXTRD = 9446
  #DISTORM_I_PEXTRQ = 9454
  #DISTORM_I_PEXTRW = 6311
  #DISTORM_I_PF2ID = 1914
  #DISTORM_I_PF2IW = 1907
  #DISTORM_I_PFACC = 2028
  #DISTORM_I_PFADD = 1977
  #DISTORM_I_PFCMPEQ = 2035
  #DISTORM_I_PFCMPGE = 1938
  #DISTORM_I_PFCMPGT = 1984
  #DISTORM_I_PFMAX = 1993
  #DISTORM_I_PFMIN = 1947
  #DISTORM_I_PFMUL = 2044
  #DISTORM_I_PFNACC = 1921
  #DISTORM_I_PFPNACC = 1929
  #DISTORM_I_PFRCP = 1954
  #DISTORM_I_PFRCPIT1 = 2000
  #DISTORM_I_PFRCPIT2 = 2051
  #DISTORM_I_PFRSQIT1 = 2010
  #DISTORM_I_PFRSQRT = 1961
  #DISTORM_I_PFSUB = 1970
  #DISTORM_I_PFSUBR = 2020
  #DISTORM_I_PHADDD = 7375
  #DISTORM_I_PHADDSW = 7392
  #DISTORM_I_PHADDW = 7358
  #DISTORM_I_PHMINPOSUW = 8259
  #DISTORM_I_PHSUBD = 7451
  #DISTORM_I_PHSUBSW = 7468
  #DISTORM_I_PHSUBW = 7434
  #DISTORM_I_PI2FD = 1900
  #DISTORM_I_PI2FW = 1893
  #DISTORM_I_PINSRB = 9530
  #DISTORM_I_PINSRD = 9568
  #DISTORM_I_PINSRQ = 9576
  #DISTORM_I_PINSRW = 6294
  #DISTORM_I_PMADDUBSW = 7411
  #DISTORM_I_PMADDWD = 7073
  #DISTORM_I_PMAXSB = 8174
  #DISTORM_I_PMAXSD = 8191
  #DISTORM_I_PMAXSW = 6964
  #DISTORM_I_PMAXUB = 6648
  #DISTORM_I_PMAXUD = 8225
  #DISTORM_I_PMAXUW = 8208
  #DISTORM_I_PMINSB = 8106
  #DISTORM_I_PMINSD = 8123
  #DISTORM_I_PMINSW = 6902
  #DISTORM_I_PMINUB = 6590
  #DISTORM_I_PMINUD = 8157
  #DISTORM_I_PMINUW = 8140
  #DISTORM_I_PMOVMSKB = 6531
  #DISTORM_I_PMOVSXBD = 7754
  #DISTORM_I_PMOVSXBQ = 7775
  #DISTORM_I_PMOVSXBW = 7733
  #DISTORM_I_PMOVSXDQ = 7838
  #DISTORM_I_PMOVSXWD = 7796
  #DISTORM_I_PMOVSXWQ = 7817
  #DISTORM_I_PMOVZXBD = 7982
  #DISTORM_I_PMOVZXBQ = 8003
  #DISTORM_I_PMOVZXBW = 7961
  #DISTORM_I_PMOVZXDQ = 8066
  #DISTORM_I_PMOVZXWD = 8024
  #DISTORM_I_PMOVZXWQ = 8045
  #DISTORM_I_PMULDQ = 7859
  #DISTORM_I_PMULHRSW = 7538
  #DISTORM_I_PMULHRW = 2061
  #DISTORM_I_PMULHUW = 6740
  #DISTORM_I_PMULHW = 6759
  #DISTORM_I_PMULLD = 8242
  #DISTORM_I_PMULLW = 6496
  #DISTORM_I_PMULUDQ = 7054
  #DISTORM_I_POP = 22
  #DISTORM_I_POPA = 98
  #DISTORM_I_POPCNT = 4338
  #DISTORM_I_POPF = 277
  #DISTORM_I_POR = 6919
  #DISTORM_I_PREFETCH = 1872
  #DISTORM_I_PREFETCHNTA = 2402
  #DISTORM_I_PREFETCHT0 = 2415
  #DISTORM_I_PREFETCHT1 = 2427
  #DISTORM_I_PREFETCHT2 = 2439
  #DISTORM_I_PREFETCHW = 1882
  #DISTORM_I_PSADBW = 7092
  #DISTORM_I_PSHUFB = 7341
  #DISTORM_I_PSHUFD = 3988
  #DISTORM_I_PSHUFHW = 3996
  #DISTORM_I_PSHUFLW = 4005
  #DISTORM_I_PSHUFW = 3980
  #DISTORM_I_PSIGNB = 7487
  #DISTORM_I_PSIGND = 7521
  #DISTORM_I_PSIGNW = 7504
  #DISTORM_I_PSLLD = 7024
  #DISTORM_I_PSLLDQ = 9847
  #DISTORM_I_PSLLQ = 7039
  #DISTORM_I_PSLLW = 7009
  #DISTORM_I_PSRAD = 6710
  #DISTORM_I_PSRAW = 6695
  #DISTORM_I_PSRLD = 6451
  #DISTORM_I_PSRLDQ = 9830
  #DISTORM_I_PSRLQ = 6466
  #DISTORM_I_PSRLW = 6436
  #DISTORM_I_PSUBB = 7144
  #DISTORM_I_PSUBD = 7174
  #DISTORM_I_PSUBQ = 7189
  #DISTORM_I_PSUBSB = 6868
  #DISTORM_I_PSUBSW = 6885
  #DISTORM_I_PSUBUSB = 6552
  #DISTORM_I_PSUBUSW = 6571
  #DISTORM_I_PSUBW = 7159
  #DISTORM_I_PSWAPD = 2070
  #DISTORM_I_PTEST = 7629
  #DISTORM_I_PUNPCKHBW = 3780
  #DISTORM_I_PUNPCKHDQ = 3826
  #DISTORM_I_PUNPCKHQDQ = 3895
  #DISTORM_I_PUNPCKHWD = 3803
  #DISTORM_I_PUNPCKLBW = 3612
  #DISTORM_I_PUNPCKLDQ = 3658
  #DISTORM_I_PUNPCKLQDQ = 3870
  #DISTORM_I_PUNPCKLWD = 3635
  #DISTORM_I_PUSH = 16
  #DISTORM_I_PUSHA = 91
  #DISTORM_I_PUSHF = 270
  #DISTORM_I_PXOR = 6981
  #DISTORM_I_RCL = 977
  #DISTORM_I_RCPPS = 2953
  #DISTORM_I_RCPSS = 2960
  #DISTORM_I_RCR = 982
  #DISTORM_I_RDFSBASE = 9882
  #DISTORM_I_RDGSBASE = 9912
  #DISTORM_I_RDMSR = 600
  #DISTORM_I_RDPMC = 607
  #DISTORM_I_RDRAND = 10026
  #DISTORM_I_RDTSC = 593
  #DISTORM_I_RDTSCP = 1864
  #DISTORM_I_RET = 325
  #DISTORM_I_RETF = 354
  #DISTORM_I_ROL = 967
  #DISTORM_I_ROR = 972
  #DISTORM_I_ROUNDPD = 9296
  #DISTORM_I_ROUNDPS = 9277
  #DISTORM_I_ROUNDSD = 9334
  #DISTORM_I_ROUNDSS = 9315
  #DISTORM_I_RSM = 882
  #DISTORM_I_RSQRTPS = 2915
  #DISTORM_I_RSQRTSS = 2924
  #DISTORM_I_SAHF = 283
  #DISTORM_I_SAL = 997
  #DISTORM_I_SALC = 394
  #DISTORM_I_SAR = 1002
  #DISTORM_I_SBB = 36
  #DISTORM_I_SCAS = 319
  #DISTORM_I_SETA = 807
  #DISTORM_I_SETAE = 780
  #DISTORM_I_SETB = 774
  #DISTORM_I_SETBE = 800
  #DISTORM_I_SETG = 859
  #DISTORM_I_SETGE = 845
  #DISTORM_I_SETL = 839
  #DISTORM_I_SETLE = 852
  #DISTORM_I_SETNO = 767
  #DISTORM_I_SETNP = 832
  #DISTORM_I_SETNS = 819
  #DISTORM_I_SETNZ = 793
  #DISTORM_I_SETO = 761
  #DISTORM_I_SETP = 826
  #DISTORM_I_SETS = 813
  #DISTORM_I_SETZ = 787
  #DISTORM_I_SFENCE = 4321
  #DISTORM_I_SGDT = 1675
  #DISTORM_I_SHL = 987
  #DISTORM_I_SHLD = 876
  #DISTORM_I_SHR = 992
  #DISTORM_I_SHRD = 892
  #DISTORM_I_SHUFPD = 6336
  #DISTORM_I_SHUFPS = 6328
  #DISTORM_I_SIDT = 1681
  #DISTORM_I_SKINIT = 1839
  #DISTORM_I_SLDT = 1641
  #DISTORM_I_SMSW = 1699
  #DISTORM_I_SQRTPD = 2855
  #DISTORM_I_SQRTPS = 2847
  #DISTORM_I_SQRTSD = 2871
  #DISTORM_I_SQRTSS = 2863
  #DISTORM_I_STC = 497
  #DISTORM_I_STD = 517
  #DISTORM_I_STGI = 1827
  #DISTORM_I_STI = 507
  #DISTORM_I_STMXCSR = 9951
  #DISTORM_I_STOS = 307
  #DISTORM_I_STR = 1647
  #DISTORM_I_SUB = 51
  #DISTORM_I_SUBPD = 3379
  #DISTORM_I_SUBPS = 3372
  #DISTORM_I_SUBSD = 3393
  #DISTORM_I_SUBSS = 3386
  #DISTORM_I_SWAPGS = 1856
  #DISTORM_I_SYSCALL = 532
  #DISTORM_I_SYSENTER = 614
  #DISTORM_I_SYSEXIT = 624
  #DISTORM_I_SYSRET = 547
  #DISTORM_I_TEST = 206
  #DISTORM_I_TZCNT = 4351
  #DISTORM_I_UCOMISD = 2742
  #DISTORM_I_UCOMISS = 2733
  #DISTORM_I_UD2 = 569
  #DISTORM_I_UNPCKHPD = 2296
  #DISTORM_I_UNPCKHPS = 2286
  #DISTORM_I_UNPCKLPD = 2254
  #DISTORM_I_UNPCKLPS = 2244
  #DISTORM_I_VADDPD = 3139
  #DISTORM_I_VADDPS = 3131
  #DISTORM_I_VADDSD = 3155
  #DISTORM_I_VADDSS = 3147
  #DISTORM_I_VADDSUBPD = 6414
  #DISTORM_I_VADDSUBPS = 6425
  #DISTORM_I_VAESDEC = 9217
  #DISTORM_I_VAESDECLAST = 9238
  #DISTORM_I_VAESENC = 9175
  #DISTORM_I_VAESENCLAST = 9196
  #DISTORM_I_VAESIMC = 9158
  #DISTORM_I_VAESKEYGENASSIST = 9812
  #DISTORM_I_VANDNPD = 3038
  #DISTORM_I_VANDNPS = 3029
  #DISTORM_I_VANDPD = 3005
  #DISTORM_I_VANDPS = 2997
  #DISTORM_I_VBLENDPD = 9381
  #DISTORM_I_VBLENDPS = 9362
  #DISTORM_I_VBLENDVPD = 9681
  #DISTORM_I_VBLENDVPS = 9670
  #DISTORM_I_VBROADCASTF128 = 7672
  #DISTORM_I_VBROADCASTSD = 7658
  #DISTORM_I_VBROADCASTSS = 7644
  #DISTORM_I_VCMPEQPD = 5088
  #DISTORM_I_VCMPEQPS = 4686
  #DISTORM_I_VCMPEQSD = 5892
  #DISTORM_I_VCMPEQSS = 5490
  #DISTORM_I_VCMPEQ_OSPD = 5269
  #DISTORM_I_VCMPEQ_OSPS = 4867
  #DISTORM_I_VCMPEQ_OSSD = 6073
  #DISTORM_I_VCMPEQ_OSSS = 5671
  #DISTORM_I_VCMPEQ_UQPD = 5175
  #DISTORM_I_VCMPEQ_UQPS = 4773
  #DISTORM_I_VCMPEQ_UQSD = 5979
  #DISTORM_I_VCMPEQ_UQSS = 5577
  #DISTORM_I_VCMPEQ_USPD = 5378
  #DISTORM_I_VCMPEQ_USPS = 4976
  #DISTORM_I_VCMPEQ_USSD = 6182
  #DISTORM_I_VCMPEQ_USSS = 5780
  #DISTORM_I_VCMPFALSEPD = 5210
  #DISTORM_I_VCMPFALSEPS = 4808
  #DISTORM_I_VCMPFALSESD = 6014
  #DISTORM_I_VCMPFALSESS = 5612
  #DISTORM_I_VCMPFALSE_OSPD = 5419
  #DISTORM_I_VCMPFALSE_OSPS = 5017
  #DISTORM_I_VCMPFALSE_OSSD = 6223
  #DISTORM_I_VCMPFALSE_OSSS = 5821
  #DISTORM_I_VCMPGEPD = 5237
  #DISTORM_I_VCMPGEPS = 4835
  #DISTORM_I_VCMPGESD = 6041
  #DISTORM_I_VCMPGESS = 5639
  #DISTORM_I_VCMPGE_OQPD = 5449
  #DISTORM_I_VCMPGE_OQPS = 5047
  #DISTORM_I_VCMPGE_OQSD = 6253
  #DISTORM_I_VCMPGE_OQSS = 5851
  #DISTORM_I_VCMPGTPD = 5247
  #DISTORM_I_VCMPGTPS = 4845
  #DISTORM_I_VCMPGTSD = 6051
  #DISTORM_I_VCMPGTSS = 5649
  #DISTORM_I_VCMPGT_OQPD = 5462
  #DISTORM_I_VCMPGT_OQPS = 5060
  #DISTORM_I_VCMPGT_OQSD = 6266
  #DISTORM_I_VCMPGT_OQSS = 5864
  #DISTORM_I_VCMPLEPD = 5108
  #DISTORM_I_VCMPLEPS = 4706
  #DISTORM_I_VCMPLESD = 5912
  #DISTORM_I_VCMPLESS = 5510
  #DISTORM_I_VCMPLE_OQPD = 5295
  #DISTORM_I_VCMPLE_OQPS = 4893
  #DISTORM_I_VCMPLE_OQSD = 6099
  #DISTORM_I_VCMPLE_OQSS = 5697
  #DISTORM_I_VCMPLTPD = 5098
  #DISTORM_I_VCMPLTPS = 4696
  #DISTORM_I_VCMPLTSD = 5902
  #DISTORM_I_VCMPLTSS = 5500
  #DISTORM_I_VCMPLT_OQPD = 5282
  #DISTORM_I_VCMPLT_OQPS = 4880
  #DISTORM_I_VCMPLT_OQSD = 6086
  #DISTORM_I_VCMPLT_OQSS = 5684
  #DISTORM_I_VCMPNEQPD = 5131
  #DISTORM_I_VCMPNEQPS = 4729
  #DISTORM_I_VCMPNEQSD = 5935
  #DISTORM_I_VCMPNEQSS = 5533
  #DISTORM_I_VCMPNEQ_OQPD = 5223
  #DISTORM_I_VCMPNEQ_OQPS = 4821
  #DISTORM_I_VCMPNEQ_OQSD = 6027
  #DISTORM_I_VCMPNEQ_OQSS = 5625
  #DISTORM_I_VCMPNEQ_OSPD = 5435
  #DISTORM_I_VCMPNEQ_OSPS = 5033
  #DISTORM_I_VCMPNEQ_OSSD = 6239
  #DISTORM_I_VCMPNEQ_OSSS = 5837
  #DISTORM_I_VCMPNEQ_USPD = 5323
  #DISTORM_I_VCMPNEQ_USPS = 4921
  #DISTORM_I_VCMPNEQ_USSD = 6127
  #DISTORM_I_VCMPNEQ_USSS = 5725
  #DISTORM_I_VCMPNGEPD = 5188
  #DISTORM_I_VCMPNGEPS = 4786
  #DISTORM_I_VCMPNGESD = 5992
  #DISTORM_I_VCMPNGESS = 5590
  #DISTORM_I_VCMPNGE_UQPD = 5391
  #DISTORM_I_VCMPNGE_UQPS = 4989
  #DISTORM_I_VCMPNGE_UQSD = 6195
  #DISTORM_I_VCMPNGE_UQSS = 5793
  #DISTORM_I_VCMPNGTPD = 5199
  #DISTORM_I_VCMPNGTPS = 4797
  #DISTORM_I_VCMPNGTSD = 6003
  #DISTORM_I_VCMPNGTSS = 5601
  #DISTORM_I_VCMPNGT_UQPD = 5405
  #DISTORM_I_VCMPNGT_UQPS = 5003
  #DISTORM_I_VCMPNGT_UQSD = 6209
  #DISTORM_I_VCMPNGT_UQSS = 5807
  #DISTORM_I_VCMPNLEPD = 5153
  #DISTORM_I_VCMPNLEPS = 4751
  #DISTORM_I_VCMPNLESD = 5957
  #DISTORM_I_VCMPNLESS = 5555
  #DISTORM_I_VCMPNLE_UQPD = 5351
  #DISTORM_I_VCMPNLE_UQPS = 4949
  #DISTORM_I_VCMPNLE_UQSD = 6155
  #DISTORM_I_VCMPNLE_UQSS = 5753
  #DISTORM_I_VCMPNLTPD = 5142
  #DISTORM_I_VCMPNLTPS = 4740
  #DISTORM_I_VCMPNLTSD = 5946
  #DISTORM_I_VCMPNLTSS = 5544
  #DISTORM_I_VCMPNLT_UQPD = 5337
  #DISTORM_I_VCMPNLT_UQPS = 4935
  #DISTORM_I_VCMPNLT_UQSD = 6141
  #DISTORM_I_VCMPNLT_UQSS = 5739
  #DISTORM_I_VCMPORDPD = 5164
  #DISTORM_I_VCMPORDPS = 4762
  #DISTORM_I_VCMPORDSD = 5968
  #DISTORM_I_VCMPORDSS = 5566
  #DISTORM_I_VCMPORD_SPD = 5365
  #DISTORM_I_VCMPORD_SPS = 4963
  #DISTORM_I_VCMPORD_SSD = 6169
  #DISTORM_I_VCMPORD_SSS = 5767
  #DISTORM_I_VCMPTRUEPD = 5257
  #DISTORM_I_VCMPTRUEPS = 4855
  #DISTORM_I_VCMPTRUESD = 6061
  #DISTORM_I_VCMPTRUESS = 5659
  #DISTORM_I_VCMPTRUE_USPD = 5475
  #DISTORM_I_VCMPTRUE_USPS = 5073
  #DISTORM_I_VCMPTRUE_USSD = 6279
  #DISTORM_I_VCMPTRUE_USSS = 5877
  #DISTORM_I_VCMPUNORDPD = 5118
  #DISTORM_I_VCMPUNORDPS = 4716
  #DISTORM_I_VCMPUNORDSD = 5922
  #DISTORM_I_VCMPUNORDSS = 5520
  #DISTORM_I_VCMPUNORD_SPD = 5308
  #DISTORM_I_VCMPUNORD_SPS = 4906
  #DISTORM_I_VCMPUNORD_SSD = 6112
  #DISTORM_I_VCMPUNORD_SSS = 5710
  #DISTORM_I_VCOMISD = 2796
  #DISTORM_I_VCOMISS = 2787
  #DISTORM_I_VCVTDQ2PD = 6819
  #DISTORM_I_VCVTDQ2PS = 3338
  #DISTORM_I_VCVTPD2DQ = 6830
  #DISTORM_I_VCVTPD2PS = 3274
  #DISTORM_I_VCVTPS2DQ = 3349
  #DISTORM_I_VCVTPS2PD = 3263
  #DISTORM_I_VCVTSD2SI = 2722
  #DISTORM_I_VCVTSD2SS = 3296
  #DISTORM_I_VCVTSI2SD = 2536
  #DISTORM_I_VCVTSI2SS = 2525
  #DISTORM_I_VCVTSS2SD = 3285
  #DISTORM_I_VCVTSS2SI = 2711
  #DISTORM_I_VCVTTPD2DQ = 6807
  #DISTORM_I_VCVTTPS2DQ = 3360
  #DISTORM_I_VCVTTSD2SI = 2659
  #DISTORM_I_VCVTTSS2SI = 2647
  #DISTORM_I_VDIVPD = 3528
  #DISTORM_I_VDIVPS = 3520
  #DISTORM_I_VDIVSD = 3544
  #DISTORM_I_VDIVSS = 3536
  #DISTORM_I_VDPPD = 9621
  #DISTORM_I_VDPPS = 9608
  #DISTORM_I_VERR = 1663
  #DISTORM_I_VERW = 1669
  #DISTORM_I_VEXTRACTF128 = 9516
  #DISTORM_I_VEXTRACTPS = 9491
  #DISTORM_I_VFMADD132PD = 8387
  #DISTORM_I_VFMADD132PS = 8374
  #DISTORM_I_VFMADD132SD = 8413
  #DISTORM_I_VFMADD132SS = 8400
  #DISTORM_I_VFMADD213PD = 8667
  #DISTORM_I_VFMADD213PS = 8654
  #DISTORM_I_VFMADD213SD = 8693
  #DISTORM_I_VFMADD213SS = 8680
  #DISTORM_I_VFMADD231PD = 8947
  #DISTORM_I_VFMADD231PS = 8934
  #DISTORM_I_VFMADD231SD = 8973
  #DISTORM_I_VFMADD231SS = 8960
  #DISTORM_I_VFMADDSUB132PD = 8326
  #DISTORM_I_VFMADDSUB132PS = 8310
  #DISTORM_I_VFMADDSUB213PD = 8606
  #DISTORM_I_VFMADDSUB213PS = 8590
  #DISTORM_I_VFMADDSUB231PD = 8886
  #DISTORM_I_VFMADDSUB231PS = 8870
  #DISTORM_I_VFMSUB132PD = 8439
  #DISTORM_I_VFMSUB132PS = 8426
  #DISTORM_I_VFMSUB132SD = 8465
  #DISTORM_I_VFMSUB132SS = 8452
  #DISTORM_I_VFMSUB213PD = 8719
  #DISTORM_I_VFMSUB213PS = 8706
  #DISTORM_I_VFMSUB213SD = 8745
  #DISTORM_I_VFMSUB213SS = 8732
  #DISTORM_I_VFMSUB231PD = 8999
  #DISTORM_I_VFMSUB231PS = 8986
  #DISTORM_I_VFMSUB231SD = 9025
  #DISTORM_I_VFMSUB231SS = 9012
  #DISTORM_I_VFMSUBADD132PD = 8358
  #DISTORM_I_VFMSUBADD132PS = 8342
  #DISTORM_I_VFMSUBADD213PD = 8638
  #DISTORM_I_VFMSUBADD213PS = 8622
  #DISTORM_I_VFMSUBADD231PD = 8918
  #DISTORM_I_VFMSUBADD231PS = 8902
  #DISTORM_I_VFNMADD132PD = 8492
  #DISTORM_I_VFNMADD132PS = 8478
  #DISTORM_I_VFNMADD132SD = 8520
  #DISTORM_I_VFNMADD132SS = 8506
  #DISTORM_I_VFNMADD213PD = 8772
  #DISTORM_I_VFNMADD213PS = 8758
  #DISTORM_I_VFNMADD213SD = 8800
  #DISTORM_I_VFNMADD213SS = 8786
  #DISTORM_I_VFNMADD231PD = 9052
  #DISTORM_I_VFNMADD231PS = 9038
  #DISTORM_I_VFNMADD231SD = 9080
  #DISTORM_I_VFNMADD231SS = 9066
  #DISTORM_I_VFNMSUB132PD = 8548
  #DISTORM_I_VFNMSUB132PS = 8534
  #DISTORM_I_VFNMSUB132SD = 8576
  #DISTORM_I_VFNMSUB132SS = 8562
  #DISTORM_I_VFNMSUB213PD = 8828
  #DISTORM_I_VFNMSUB213PS = 8814
  #DISTORM_I_VFNMSUB213SD = 8856
  #DISTORM_I_VFNMSUB213SS = 8842
  #DISTORM_I_VFNMSUB231PD = 9108
  #DISTORM_I_VFNMSUB231PS = 9094
  #DISTORM_I_VFNMSUB231SD = 9136
  #DISTORM_I_VFNMSUB231SS = 9122
  #DISTORM_I_VHADDPD = 4197
  #DISTORM_I_VHADDPS = 4206
  #DISTORM_I_VHSUBPD = 4231
  #DISTORM_I_VHSUBPS = 4240
  #DISTORM_I_VINSERTF128 = 9503
  #DISTORM_I_VINSERTPS = 9557
  #DISTORM_I_VLDDQU = 7001
  #DISTORM_I_VLDMXCSR = 9941
  #DISTORM_I_VMASKMOVDQU = 7131
  #DISTORM_I_VMASKMOVPD = 7949
  #DISTORM_I_VMASKMOVPS = 7937
  #DISTORM_I_VMAXPD = 3588
  #DISTORM_I_VMAXPS = 3580
  #DISTORM_I_VMAXSD = 3604
  #DISTORM_I_VMAXSS = 3596
  #DISTORM_I_VMCALL = 1719
  #DISTORM_I_VMCLEAR = 9989
  #DISTORM_I_VMFUNC = 1787
  #DISTORM_I_VMINPD = 3468
  #DISTORM_I_VMINPS = 3460
  #DISTORM_I_VMINSD = 3484
  #DISTORM_I_VMINSS = 3476
  #DISTORM_I_VMLAUNCH = 1727
  #DISTORM_I_VMLOAD = 1811
  #DISTORM_I_VMMCALL = 1802
  #DISTORM_I_VMOVAPD = 2476
  #DISTORM_I_VMOVAPS = 2467
  #DISTORM_I_VMOVD = 3932
  #DISTORM_I_VMOVDDUP = 2234
  #DISTORM_I_VMOVDQA = 3962
  #DISTORM_I_VMOVDQU = 3971
  #DISTORM_I_VMOVHLPS = 2195
  #DISTORM_I_VMOVHPD = 2382
  #DISTORM_I_VMOVHPS = 2373
  #DISTORM_I_VMOVLHPS = 2363
  #DISTORM_I_VMOVLPD = 2214
  #DISTORM_I_VMOVLPS = 2205
  #DISTORM_I_VMOVMSKPD = 2836
  #DISTORM_I_VMOVMSKPS = 2825
  #DISTORM_I_VMOVNTDQ = 6858
  #DISTORM_I_VMOVNTDQA = 7905
  #DISTORM_I_VMOVNTPD = 2593
  #DISTORM_I_VMOVNTPS = 2583
  #DISTORM_I_VMOVQ = 3939
  #DISTORM_I_VMOVSD = 2143
  #DISTORM_I_VMOVSHDUP = 2391
  #DISTORM_I_VMOVSLDUP = 2223
  #DISTORM_I_VMOVSS = 2135
  #DISTORM_I_VMOVUPD = 2126
  #DISTORM_I_VMOVUPS = 2117
  #DISTORM_I_VMPSADBW = 9637
  #DISTORM_I_VMPTRLD = 9980
  #DISTORM_I_VMPTRST = 6385
  #DISTORM_I_VMREAD = 4128
  #DISTORM_I_VMRESUME = 1737
  #DISTORM_I_VMRUN = 1795
  #DISTORM_I_VMSAVE = 1819
  #DISTORM_I_VMULPD = 3199
  #DISTORM_I_VMULPS = 3191
  #DISTORM_I_VMULSD = 3215
  #DISTORM_I_VMULSS = 3207
  #DISTORM_I_VMWRITE = 4152
  #DISTORM_I_VMXOFF = 1747
  #DISTORM_I_VMXON = 9998
  #DISTORM_I_VORPD = 3066
  #DISTORM_I_VORPS = 3059
  #DISTORM_I_VPABSB = 7695
  #DISTORM_I_VPABSD = 7725
  #DISTORM_I_VPABSW = 7710
  #DISTORM_I_VPACKSSDW = 3859
  #DISTORM_I_VPACKSSWB = 3691
  #DISTORM_I_VPACKUSDW = 7926
  #DISTORM_I_VPACKUSWB = 3769
  #DISTORM_I_VPADDB = 7211
  #DISTORM_I_VPADDD = 7241
  #DISTORM_I_VPADDQ = 6488
  #DISTORM_I_VPADDSB = 6938
  #DISTORM_I_VPADDSW = 6955
  #DISTORM_I_VPADDUSW = 6629
  #DISTORM_I_VPADDW = 7226
  #DISTORM_I_VPALIGNR = 9419
  #DISTORM_I_VPAND = 6613
  #DISTORM_I_VPANDN = 6672
  #DISTORM_I_VPAVGB = 6687
  #DISTORM_I_VPAVGW = 6732
  #DISTORM_I_VPBLENDVB = 9692
  #DISTORM_I_VPBLENDW = 9400
  #DISTORM_I_VPCLMULQDQ = 9658
  #DISTORM_I_VPCMPEQB = 4052
  #DISTORM_I_VPCMPEQD = 4090
  #DISTORM_I_VPCMPEQQ = 7885
  #DISTORM_I_VPCMPEQW = 4071
  #DISTORM_I_VPCMPESTRI = 9737
  #DISTORM_I_VPCMPESTRM = 9714
  #DISTORM_I_VPCMPGTB = 3711
  #DISTORM_I_VPCMPGTD = 3749
  #DISTORM_I_VPCMPGTQ = 8096
  #DISTORM_I_VPCMPGTW = 3730
  #DISTORM_I_VPCMPISTRI = 9783
  #DISTORM_I_VPCMPISTRM = 9760
  #DISTORM_I_VPERM2F128 = 9265
  #DISTORM_I_VPERMILPD = 7570
  #DISTORM_I_VPERMILPS = 7559
  #DISTORM_I_VPEXTRB = 9437
  #DISTORM_I_VPEXTRD = 9462
  #DISTORM_I_VPEXTRQ = 9471
  #DISTORM_I_VPEXTRW = 6319
  #DISTORM_I_VPHADDD = 7383
  #DISTORM_I_VPHADDSW = 7401
  #DISTORM_I_VPHADDW = 7366
  #DISTORM_I_VPHMINPOSUW = 8271
  #DISTORM_I_VPHSUBD = 7459
  #DISTORM_I_VPHSUBSW = 7477
  #DISTORM_I_VPHSUBW = 7442
  #DISTORM_I_VPINSRB = 9538
  #DISTORM_I_VPINSRD = 9584
  #DISTORM_I_VPINSRQ = 9593
  #DISTORM_I_VPINSRW = 6302
  #DISTORM_I_VPMADDUBSW = 7422
  #DISTORM_I_VPMADDWD = 7082
  #DISTORM_I_VPMAXSB = 8182
  #DISTORM_I_VPMAXSD = 8199
  #DISTORM_I_VPMAXSW = 6972
  #DISTORM_I_VPMAXUB = 6656
  #DISTORM_I_VPMAXUD = 8233
  #DISTORM_I_VPMAXUW = 8216
  #DISTORM_I_VPMINSB = 8114
  #DISTORM_I_VPMINSD = 8131
  #DISTORM_I_VPMINSW = 6910
  #DISTORM_I_VPMINUB = 6598
  #DISTORM_I_VPMINUD = 8165
  #DISTORM_I_VPMINUW = 8148
  #DISTORM_I_VPMOVMSKB = 6541
  #DISTORM_I_VPMOVSXBD = 7764
  #DISTORM_I_VPMOVSXBQ = 7785
  #DISTORM_I_VPMOVSXBW = 7743
  #DISTORM_I_VPMOVSXDQ = 7848
  #DISTORM_I_VPMOVSXWD = 7806
  #DISTORM_I_VPMOVSXWQ = 7827
  #DISTORM_I_VPMOVZXBD = 7992
  #DISTORM_I_VPMOVZXBQ = 8013
  #DISTORM_I_VPMOVZXBW = 7971
  #DISTORM_I_VPMOVZXDQ = 8076
  #DISTORM_I_VPMOVZXWD = 8034
  #DISTORM_I_VPMOVZXWQ = 8055
  #DISTORM_I_VPMULDQ = 7867
  #DISTORM_I_VPMULHRSW = 7548
  #DISTORM_I_VPMULHUW = 6749
  #DISTORM_I_VPMULHW = 6767
  #DISTORM_I_VPMULLD = 8250
  #DISTORM_I_VPMULLW = 6504
  #DISTORM_I_VPMULUDQ = 7063
  #DISTORM_I_VPOR = 6924
  #DISTORM_I_VPSADBW = 7100
  #DISTORM_I_VPSHUFB = 7349
  #DISTORM_I_VPSHUFD = 4014
  #DISTORM_I_VPSHUFHW = 4023
  #DISTORM_I_VPSHUFLW = 4033
  #DISTORM_I_VPSIGNB = 7495
  #DISTORM_I_VPSIGND = 7529
  #DISTORM_I_VPSIGNW = 7512
  #DISTORM_I_VPSLLD = 7031
  #DISTORM_I_VPSLLDQ = 9855
  #DISTORM_I_VPSLLQ = 7046
  #DISTORM_I_VPSLLW = 7016
  #DISTORM_I_VPSRAD = 6717
  #DISTORM_I_VPSRAW = 6702
  #DISTORM_I_VPSRLD = 6458
  #DISTORM_I_VPSRLDQ = 9838
  #DISTORM_I_VPSRLQ = 6473
  #DISTORM_I_VPSRLW = 6443
  #DISTORM_I_VPSUBB = 7151
  #DISTORM_I_VPSUBD = 7181
  #DISTORM_I_VPSUBQ = 7196
  #DISTORM_I_VPSUBSB = 6876
  #DISTORM_I_VPSUBSW = 6893
  #DISTORM_I_VPSUBUSB = 6561
  #DISTORM_I_VPSUBUSW = 6580
  #DISTORM_I_VPSUBW = 7166
  #DISTORM_I_VPTEST = 7636
  #DISTORM_I_VPUNPCKHBW = 3791
  #DISTORM_I_VPUNPCKHDQ = 3837
  #DISTORM_I_VPUNPCKHQDQ = 3907
  #DISTORM_I_VPUNPCKHWD = 3814
  #DISTORM_I_VPUNPCKLBW = 3623
  #DISTORM_I_VPUNPCKLDQ = 3669
  #DISTORM_I_VPUNPCKLQDQ = 3882
  #DISTORM_I_VPUNPCKLWD = 3646
  #DISTORM_I_VPXOR = 6987
  #DISTORM_I_VRCPPS = 2967
  #DISTORM_I_VRCPSS = 2975
  #DISTORM_I_VROUNDPD = 9305
  #DISTORM_I_VROUNDPS = 9286
  #DISTORM_I_VROUNDSD = 9343
  #DISTORM_I_VROUNDSS = 9324
  #DISTORM_I_VRSQRTPS = 2933
  #DISTORM_I_VRSQRTSS = 2943
  #DISTORM_I_VSHUFPD = 6353
  #DISTORM_I_VSHUFPS = 6344
  #DISTORM_I_VSQRTPD = 2888
  #DISTORM_I_VSQRTPS = 2879
  #DISTORM_I_VSQRTSD = 2906
  #DISTORM_I_VSQRTSS = 2897
  #DISTORM_I_VSTMXCSR = 9970
  #DISTORM_I_VSUBPD = 3408
  #DISTORM_I_VSUBPS = 3400
  #DISTORM_I_VSUBSD = 3424
  #DISTORM_I_VSUBSS = 3416
  #DISTORM_I_VTESTPD = 7590
  #DISTORM_I_VTESTPS = 7581
  #DISTORM_I_VUCOMISD = 2761
  #DISTORM_I_VUCOMISS = 2751
  #DISTORM_I_VUNPCKHPD = 2317
  #DISTORM_I_VUNPCKHPS = 2306
  #DISTORM_I_VUNPCKLPD = 2275
  #DISTORM_I_VUNPCKLPS = 2264
  #DISTORM_I_VXORPD = 3095
  #DISTORM_I_VXORPS = 3087
  #DISTORM_I_VZEROALL = 4118
  #DISTORM_I_VZEROUPPER = 4106
  #DISTORM_I_WAIT = 10020
  #DISTORM_I_WBINVD = 561
  #DISTORM_I_WRFSBASE = 9931
  #DISTORM_I_WRGSBASE = 9960
  #DISTORM_I_WRMSR = 586
  #DISTORM_I_XADD = 946
  #DISTORM_I_XCHG = 212
  #DISTORM_I_XGETBV = 1771
  #DISTORM_I_XLAT = 400
  #DISTORM_I_XOR = 61
  #DISTORM_I_XORPD = 3080
  #DISTORM_I_XORPS = 3073
  #DISTORM_I_XRSTOR = 4273
  #DISTORM_I_XRSTOR64 = 4281
  #DISTORM_I_XSAVE = 4249
  #DISTORM_I_XSAVE64 = 4256
  #DISTORM_I_XSAVEOPT = 4299
  #DISTORM_I_XSAVEOPT64 = 4309
  #DISTORM_I_XSETBV = 1779
  #DISTORM_I__3DNOW = 10034
EndEnumeration


; _RegisterType

Enumeration
  #DISTORM_R_RAX
  #DISTORM_R_RCX
  #DISTORM_R_RDX
  #DISTORM_R_RBX
  #DISTORM_R_RSP
  #DISTORM_R_RBP
  #DISTORM_R_RSI
  #DISTORM_R_RDI
  #DISTORM_R_R8
  #DISTORM_R_R9
  #DISTORM_R_R10
  #DISTORM_R_R11
  #DISTORM_R_R12
  #DISTORM_R_R13
  #DISTORM_R_R14
  #DISTORM_R_R15
  #DISTORM_R_EAX
  #DISTORM_R_ECX
  #DISTORM_R_EDX
  #DISTORM_R_EBX
  #DISTORM_R_ESP
  #DISTORM_R_EBP
  #DISTORM_R_ESI
  #DISTORM_R_EDI
  #DISTORM_R_R8D
  #DISTORM_R_R9D
  #DISTORM_R_R10D
  #DISTORM_R_R11D
  #DISTORM_R_R12D
  #DISTORM_R_R13D
  #DISTORM_R_R14D
  #DISTORM_R_R15D
  #DISTORM_R_AX
  #DISTORM_R_CX
  #DISTORM_R_DX
  #DISTORM_R_BX
  #DISTORM_R_SP
  #DISTORM_R_BP
  #DISTORM_R_SI
  #DISTORM_R_DI
  #DISTORM_R_R8W
  #DISTORM_R_R9W
  #DISTORM_R_R10W
  #DISTORM_R_R11W
  #DISTORM_R_R12W
  #DISTORM_R_R13W
  #DISTORM_R_R14W
  #DISTORM_R_R15W
  #DISTORM_R_AL
  #DISTORM_R_CL
  #DISTORM_R_DL
  #DISTORM_R_BL
  #DISTORM_R_AH
  #DISTORM_R_CH
  #DISTORM_R_DH
  #DISTORM_R_BH
  #DISTORM_R_R8B
  #DISTORM_R_R9B
  #DISTORM_R_R10B
  #DISTORM_R_R11B
  #DISTORM_R_R12B
  #DISTORM_R_R13B
  #DISTORM_R_R14B
  #DISTORM_R_R15B
  #DISTORM_R_SPL
  #DISTORM_R_BPL
  #DISTORM_R_SIL
  #DISTORM_R_DIL
  #DISTORM_R_ES
  #DISTORM_R_CS
  #DISTORM_R_SS
  #DISTORM_R_DS
  #DISTORM_R_FS
  #DISTORM_R_GS
  #DISTORM_R_RIP
  #DISTORM_R_ST0
  #DISTORM_R_ST1
  #DISTORM_R_ST2
  #DISTORM_R_ST3
  #DISTORM_R_ST4
  #DISTORM_R_ST5
  #DISTORM_R_ST6
  #DISTORM_R_ST7
  #DISTORM_R_MM0
  #DISTORM_R_MM1
  #DISTORM_R_MM2
  #DISTORM_R_MM3
  #DISTORM_R_MM4
  #DISTORM_R_MM5
  #DISTORM_R_MM6
  #DISTORM_R_MM7
  #DISTORM_R_XMM0
  #DISTORM_R_XMM1
  #DISTORM_R_XMM2
  #DISTORM_R_XMM3
  #DISTORM_R_XMM4
  #DISTORM_R_XMM5
  #DISTORM_R_XMM6
  #DISTORM_R_XMM7
  #DISTORM_R_XMM8
  #DISTORM_R_XMM9
  #DISTORM_R_XMM10
  #DISTORM_R_XMM11
  #DISTORM_R_XMM12
  #DISTORM_R_XMM13
  #DISTORM_R_XMM14
  #DISTORM_R_XMM15
  #DISTORM_R_YMM0
  #DISTORM_R_YMM1
  #DISTORM_R_YMM2
  #DISTORM_R_YMM3
  #DISTORM_R_YMM4
  #DISTORM_R_YMM5
  #DISTORM_R_YMM6
  #DISTORM_R_YMM7
  #DISTORM_R_YMM8
  #DISTORM_R_YMM9
  #DISTORM_R_YMM10
  #DISTORM_R_YMM11
  #DISTORM_R_YMM12
  #DISTORM_R_YMM13
  #DISTORM_R_YMM14
  #DISTORM_R_YMM15
  #DISTORM_R_CR0
  #DISTORM_R_UNUSED0
  #DISTORM_R_CR2
  #DISTORM_R_CR3
  #DISTORM_R_CR4
  #DISTORM_R_UNUSED1
  #DISTORM_R_UNUSED2
  #DISTORM_R_UNUSED3
  #DISTORM_R_CR8
  #DISTORM_R_DR0
  #DISTORM_R_DR1
  #DISTORM_R_DR2
  #DISTORM_R_DR3
  #DISTORM_R_UNUSED4
  #DISTORM_R_UNUSED5
  #DISTORM_R_DR6
  #DISTORM_R_DR7
EndEnumeration



;- =====================================
;- Prefix
;- =====================================


; Specifies the type of the extension prefix, such as: REX, 2 bytes VEX, 3 bytes VEX.


; _PrefixExtType

Enumeration
  #DISTORM_PET_NONE = 0
  #DISTORM_PET_REX
  #DISTORM_PET_VEX2BYTES
  #DISTORM_PET_VEX3BYTES
EndEnumeration

;  Specifies an index into a table of prefixes by their type.

; _PrefixIndexer

Enumeration
  #DISTORM_PFXIDX_NONE = -1
  #DISTORM_PFXIDX_REX
  #DISTORM_PFXIDX_LOREP
  #DISTORM_PFXIDX_SEG
  #DISTORM_PFXIDX_OP_SIZE
  #DISTORM_PFXIDX_ADRS
  #DISTORM_PFXIDX_MAX
EndEnumeration


; * This holds the prefixes state For the current instruction we decode.
; * decodedPrefixes includes all specific prefixes that the instruction got.
; * start is a pointer To the first prefix To take into account.
; * last is a pointer To the last byte we scanned.
; * Other pointers are used To keep track of prefixes positions And help us know If they appeared already And where.

Structure _DISTORM_PrefixState Align #PB_Structure_AlignC
  decodedPrefixes.l
  usedPrefixes.l
  *start
  *last
  *vexPos
  *rexPos
  prefixExtType.l
  unusedPrefixesMask.u
  
  ; Indicates whether the operand size prefix (0x66) was used as a mandatory prefix.
  isOpSizeMandatory.l
  
  ; If VEX prefix is used, store the VEX.vvvv field.
  vexV.l
  
  ; The fields B/X/R/W/L of REX and VEX are stored together in this byte.
  vrex.l
  
  ; Make sure pfxIndexer is LAST! Otherwise memset won't work well with it.
  
  ; Holds the offset to the prefix byte by its type.
  pfxIndexer.l[#DISTORM_PFXIDX_MAX]
EndStructure

Structure _DISTORM_PrefixState_array
  PrefixState._DISTORM_PrefixState[0]
EndStructure

; * Intel supports 6 types of prefixes, whereas AMD supports 5 types (lock is seperated from rep/nz).
; * REX is the fifth prefix type, this time I'm based on AMD64.
; * VEX is the 6th, though it can't be repeated.

#DISTORM_MAX_PREFIXES = 5

CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  ImportC #DISTORM_LIB_FULLPATH
CompilerElse
  Import #DISTORM_LIB_FULLPATH
  CompilerEndIf
  
  prefixes_is_valid.l(ch.l, dt.l)
  prefixes_ignore(*ps._DIstorm_PrefixState, pi.l)
  prefixes_ignore_all(*ps._DIstorm_PrefixState)
  prefixes_set_unused_mask.u(*ps._DIstorm_PrefixState)
  prefixes_decode(*code, codeLen.l, *ps._DIstorm_PrefixState, dt.l)
  prefixes_use_segment(defaultSeg.l, *ps._DIstorm_PrefixState, dt.l, *di._DISTORM_DInst)
EndImport



;- =====================================
;- Instructions
;- =====================================


;  * Operand type possibilities:
;  * Note "_FULL" suffix indicates To decode the operand As 16 bits Or 32 bits depends on DecodeType -
;  * actually, it depends on the decoding mode, unless there's an operand/address size prefix.
;  * For example, the code: 33 c0 could be decoded/executed As XOr AX, AX Or XOr EAX, EAX.


; _OpType

Enumeration
  ; No operand is set
  #DISTORM_OT_NONE = 0
  
  ; Read a byte(8 bits) immediate
  #DISTORM_OT_IMM8
  ; Force a read of a word(16 bits) immediate, used by ret only
  #DISTORM_OT_IMM16
  ; Read a word/dword immediate
  #DISTORM_OT_IMM_FULL
  ; Read a double-word(32 bits) immediate
  #DISTORM_OT_IMM32
  
  ; Read a signed extended byte(8 bits) immediate
  #DISTORM_OT_SEIMM8
  
  ; Special immediates For instructions which have more than one immediate
  ; which is an exception from standard instruction format.
  ; As To version v1.0: ENTER, INSERTQ, EXTRQ are the only problematic ones.
  
  ; 16 bits immediate using the first imm-slot
  #DISTORM_OT_IMM16_1
  ; 8 bits immediate using the first imm-slot
  #DISTORM_OT_IMM8_1
  ; 8 bits immediate using the second imm-slot
  #DISTORM_OT_IMM8_2
  
  ; Use a 8bit register
  #DISTORM_OT_REG8
  ; Use a 16bit register
  #DISTORM_OT_REG16
  ; Use a 16/32/64bit register
  #DISTORM_OT_REG_FULL
  ; Use a 32bit register
  #DISTORM_OT_REG32
  
  ; If used With REX the reg operand size becomes 64 bits, otherwise 32 bits.
  ; VMX instructions are promoted automatically without a REX prefix.
  
  #DISTORM_OT_REG32_64
  ; Used only by MOV CR/DR(n). Promoted with REX onlly.
  #DISTORM_OT_FREG32_64_RM
  
  ; Use or read (indirection) a 8bit register or immediate byte
  #DISTORM_OT_RM8
  ; Some instructions force 16 bits (mov sreg, rm16)
  #DISTORM_OT_RM16
  ; Use or read a 16/32/64bit register or immediate word/dword/qword
  #DISTORM_OT_RM_FULL
  
  ; 32 Or 64 bits (With REX) operand size indirection memory operand.
  ; Some instructions are promoted automatically without a REX prefix.
  
  #DISTORM_OT_RM32_64
  ; 16 or 32 bits RM. This is used only with MOVZXD instruction in 64bits.
  #DISTORM_OT_RM16_32
  ; Same as #DISTORM_OT_RMXX but POINTS to 16 bits [cannot use GENERAL-PURPOSE REG!]
  #DISTORM_OT_FPUM16
  ; Same as #DISTORM_OT_RMXX but POINTS to 32 bits (single precision) [cannot use GENERAL-PURPOSE REG!]
  #DISTORM_OT_FPUM32
  ; Same as #DISTORM_OT_RMXX but POINTS to 64 bits (double precision) [cannot use GENERAL-PURPOSE REG!]
  #DISTORM_OT_FPUM64
  ; Same as #DISTORM_OT_RMXX but POINTS to 80 bits (extended precision) [cannot use GENERAL-PURPOSE REG!]
  #DISTORM_OT_FPUM80
  
  
  ; Special operand type For SSE4 where the ModR/M might
  ; be a 32 bits register Or 8 bits memory indirection operand.
  
  #DISTORM_OT_R32_M8
  
  ; Special ModR/M For PINSRW, which need a 16 bits memory operand Or 32 bits register.
  ; In 16 bits decoding mode R32 becomes R16, operand size cannot affect this.
  
  #DISTORM_OT_R32_M16
  
  ; Special type For SSE4, ModR/M might be a 32 bits Or 64 bits (With REX) register Or
  ; a 8 bits memory indirection operand.
  
  #DISTORM_OT_R32_64_M8
  
  ; Special type For SSE4, ModR/M might be a 32 bits Or 64 bits (With REX) register Or
  ; a 16 bits memory indirection operand.
  
  #DISTORM_OT_R32_64_M16
  
  ; Special operand type For MOV reg16/32/64/mem16, segReg 8C /r. And SMSW.
  ; It supports all decoding modes, but If used As a memory indirection it's a 16 bit ModR/M indirection.
  
  #DISTORM_OT_RFULL_M16
  
  ; Use a control register
  #DISTORM_OT_CREG
  ; Use a debug register
  #DISTORM_OT_DREG
  ; Use a segment register
  #DISTORM_OT_SREG
  
  ; * SEG is encoded in the flags of the opcode itself!
  ; * This is used For specific "push SS" where SS is a segment where
  ; * each "push SS" has an absolutely different opcode byte.
  ; * We need this To detect whether an operand size prefix is used.
  
  #DISTORM_OT_SEG
  
  ; Use AL
  #DISTORM_OT_ACC8
  ; Use AX (FSTSW)
  #DISTORM_OT_ACC16
  ; Use AX/EAX/RAX
  #DISTORM_OT_ACC_FULL
  ; Use AX/EAX, no REX is possible for RAX, used only with IN/OUT which don't support 64 bit registers
  #DISTORM_OT_ACC_FULL_NOT64
  
  
  ; * Read one word (seg), And a word/dword/qword (depends on operand size) from memory.
  ; * JMP FAR [EBX] means EBX point To 16:32 ptr.
  
  #DISTORM_OT_MEM16_FULL
  ; Read one word (seg) and a word/dword/qword (depends on operand size), usually SEG:OFF, JMP 1234:1234
  #DISTORM_OT_PTR16_FULL
  ; Read one word (limit) and a dword/qword (limit) (depends on operand size), used by SGDT, SIDT, LGDT, LIDT.
  #DISTORM_OT_MEM16_3264
  
  ; Read a byte(8 bits) immediate and calculate it relatively to the current offset of the instruction being decoded
  #DISTORM_OT_RELCB
  ; Read a word/dword immediate and calculate it relatively to the current offset of the instruction being decoded
  #DISTORM_OT_RELC_FULL
  
  ; Use general memory indirection, with varying sizes:
  #DISTORM_OT_MEM
  ; Used when a memory indirection is required, but if the mod field is 11, this operand will be ignored.
  #DISTORM_OT_MEM_OPT
  #DISTORM_OT_MEM32
  ; Memory dereference for MOVNTI, either 32 or 64 bits (with REX).
  #DISTORM_OT_MEM32_64
  #DISTORM_OT_MEM64
  #DISTORM_OT_MEM128
  ; Used for cmpxchg8b/16b.
  #DISTORM_OT_MEM64_128
  
  ; Read an immediate as an absolute address, size is known by instruction, used by MOV (memory offset) only
  #DISTORM_OT_MOFFS8
  #DISTORM_OT_MOFFS_FULL
  ; Use an immediate of 1, as for SHR R/M, 1
  #DISTORM_OT_CONST1
  ; Use CL, as for SHR R/M, CL
  #DISTORM_OT_REGCL
  
  
  ; * Instruction-Block For one byte long instructions, used by INC/DEC/PUSH/POP/XCHG
  ; * REG is extracted from the value of opcode
  ; * Use a 8bit register
  
  #DISTORM_OT_IB_RB
  ; Use a 16/32/64bit register
  #DISTORM_OT_IB_R_FULL
  
  ; Use [(r)SI] as INDIRECTION, for repeatable instructions
  #DISTORM_OT_REGI_ESI
  ; Use [(r)DI] as INDIRECTION, for repeatable instructions
  #DISTORM_OT_REGI_EDI
  ; Use [(r)BX + AL] as INDIRECTIOM, used by XLAT only
  #DISTORM_OT_REGI_EBXAL
  ; Use [(r)AX] as INDIRECTION, used by AMD's SVM instructions
  #DISTORM_OT_REGI_EAX
  ; Use DX, as for OUTS DX, BYTE [SI]
  #DISTORM_OT_REGDX
  ; Use ECX in INVLPGA instruction
  #DISTORM_OT_REGECX
  
  ; FPU registers:
  #DISTORM_OT_FPU_SI ; ST(i)
  #DISTORM_OT_FPU_SSI; ST(0), ST(i)
  #DISTORM_OT_FPU_SIS; ST(i), ST(0)
  
  ; MMX registers:
  #DISTORM_OT_MM
  ; Extract the MMX register from the RM bits this time (used when the REG bits are used for opcode extension)
  #DISTORM_OT_MM_RM
  ; ModR/M points to 32 bits MMX variable
  #DISTORM_OT_MM32
  ; ModR/M points to 32 bits MMX variable
  #DISTORM_OT_MM64
  
  ; SSE registers:
  #DISTORM_OT_XMM
  ; Extract the SSE register from the RM bits this time (used when the REG bits are used for opcode extension)
  #DISTORM_OT_XMM_RM
  ; ModR/M points to 16 bits SSE variable
  #DISTORM_OT_XMM16
  ; ModR/M points to 32 bits SSE variable
  #DISTORM_OT_XMM32
  ; ModR/M points to 64 bits SSE variable
  #DISTORM_OT_XMM64
  ; ModR/M points to 128 bits SSE variable
  #DISTORM_OT_XMM128
  ; Implied XMM0 register as operand, used in SSE4.
  #DISTORM_OT_REGXMM0
  
  ; AVX operands:
  
  ; ModR/M for 32 bits.
  #DISTORM_OT_RM32
  ; Reg32/Reg64 (prefix width) or Mem8.
  #DISTORM_OT_REG32_64_M8
  ; Reg32/Reg64 (prefix width) or Mem16.
  #DISTORM_OT_REG32_64_M16
  ; Reg32/Reg 64 depends on prefix width only.
  #DISTORM_OT_WREG32_64
  ; RM32/RM64 depends on prefix width only.
  #DISTORM_OT_WRM32_64
  ; XMM or Mem32/Mem64 depends on perfix width only.
  #DISTORM_OT_WXMM32_64
  ; XMM is encoded in VEX.VVVV.
  #DISTORM_OT_VXMM
  ; XMM is encoded in the high nibble of an immediate byte.
  #DISTORM_OT_XMM_IMM
  ; YMM/XMM is dependent on VEX.L.
  #DISTORM_OT_YXMM
  ; YMM/XMM (depends on prefix length) is encoded in the high nibble of an immediate byte.
  #DISTORM_OT_YXMM_IMM
  ; YMM is encoded in reg.
  #DISTORM_OT_YMM
  ; YMM or Mem256.
  #DISTORM_OT_YMM256
  ; YMM is encoded in VEX.VVVV.
  #DISTORM_OT_VYMM
  ; YMM/XMM is dependent on VEX.L, and encoded in VEX.VVVV.
  #DISTORM_OT_VYXMM
  ; YMM/XMM or Mem64/Mem256 is dependent on VEX.L.
  #DISTORM_OT_YXMM64_256
  ; YMM/XMM or Mem128/Mem256 is dependent on VEX.L.
  #DISTORM_OT_YXMM128_256
  ; XMM or Mem64/Mem256 is dependent on VEX.L.
  #DISTORM_OT_LXMM64_128
  ; Mem128/Mem256 is dependent on VEX.L.
  #DISTORM_OT_LMEM128_256
EndEnumeration


; Flags for instruction:


; Empty flags indicator:
#DISTORM_INST_FLAGS_NONE = 0
; The instruction we are going to decode requires ModR/M encoding.
#DISTORM_INST_MODRM_REQUIRED = 1
; Special treatment for instructions which are in the divided-category but still needs the whole byte for ModR/M...
#DISTORM_INST_NOT_DIVIDED = 1 << 1

; Used explicitly in repeatable instructions,
; which needs a suffix letter in their mnemonic To specify operation-size (depend on operands).

#DISTORM_INST_16BITS = 1 << 2
; If the opcode is supported by 80286 and upper models (16/32 bits).
#DISTORM_INST_32BITS = 1 << 3

; Prefix flags (6 types: lock/rep, seg override, addr-size, oper-size, REX, VEX)
; There are several specific instructions that can follow LOCK prefix,
; note that they must be using a memory operand form, otherwise they generate an exception.

#DISTORM_INST_PRE_LOCK = 1 << 4
; REPNZ prefix for string instructions only - means an instruction can follow it.
#DISTORM_INST_PRE_REPNZ = 1 << 5
; REP prefix for string instructions only - means an instruction can follow it.
#DISTORM_INST_PRE_REP = 1 << 6
; CS override prefix.
#DISTORM_INST_PRE_CS = 1 << 7
; SS override prefix.
#DISTORM_INST_PRE_SS = 1 << 8
; DS override prefix.
#DISTORM_INST_PRE_DS = 1 << 9
; ES override prefix.
#DISTORM_INST_PRE_ES = 1 << 10
; FS override prefix. Funky Segment :)
#DISTORM_INST_PRE_FS = 1 << 11
; GS override prefix. Groovy Segment, of course not, duh !
#DISTORM_INST_PRE_GS = 1 << 12
; Switch operand size from 32 to 16 and vice versa.
#DISTORM_INST_PRE_OP_SIZE = 1 << 13
; Switch address size from 32 to 16 and vice versa.
#DISTORM_INST_PRE_ADDR_SIZE = 1 << 14
; Native instructions which needs suffix letter to indicate their operation-size (and don't depend on operands).
#DISTORM_INST_NATIVE = 1 << 15
; Use extended mnemonic, means it's an _InstInfoEx structure, which contains another mnemonic for 32 bits specifically.
#DISTORM_INST_USE_EXMNEMONIC = 1 << 16
; Use third operand, means it's an _InstInfoEx structure, which contains another operand for special instructions.
#DISTORM_INST_USE_OP3 = 1 << 17
; Use fourth operand, means it's an _InstInfoEx structure, which contains another operand for special instructions.
#DISTORM_INST_USE_OP4 = 1 << 18
; The instruction's mnemonic depends on the mod value of the ModR/M byte (mod=11, mod!=11).
#DISTORM_INST_MNEMONIC_MODRM_BASED = 1 << 19
; The instruction uses a ModR/M byte which the MOD must be 11 (for registers operands only).
#DISTORM_INST_MODRR_REQUIRED = 1 << 20
; The way of 3DNow! instructions are built, we have to handle their locating specially. Suffix imm8 tells which instruction it is.
#DISTORM_INST_3DNOW_FETCH = 1 << 21
; The instruction needs two suffixes, one for the comparison type (imm8) and the second for its operation size indication (second mnemonic).
#DISTORM_INST_PSEUDO_OPCODE = 1 << 22
; Invalid instruction at 64 bits decoding mode.
#DISTORM_INST_INVALID_64BITS = 1 << 23
; Specific instruction can be promoted to 64 bits (without REX, it is promoted automatically).
#DISTORM_INST_64BITS = 1 << 24
; Indicates the instruction must be REX prefixed in order to use 64 bits operands.
#DISTORM_INST_PRE_REX = 1 << 25
; Third mnemonic is set.
#DISTORM_INST_USE_EXMNEMONIC2 = 1 << 26
; Instruction is only valid in 64 bits decoding mode.
#DISTORM_INST_64BITS_FETCH = 1 << 27
; Forces that the ModRM-REG/Opcode field will be 0. (For EXTRQ).
#DISTORM_INST_FORCE_REG0 = 1 << 28
; Indicates that instruction is encoded with a VEX prefix.
#DISTORM_INST_PRE_VEX = 1 << 29
; Indicates that the instruction is encoded with a ModRM byte (REG field specifically).
#DISTORM_INST_MODRM_INCLUDED = 1 << 30
; Indicates that the first (/destination) operand of the instruction is writable.
#DISTORM_INST_DST_WR = 1 << 31


#DISTORM_INST_PRE_REPS = #DISTORM_INST_PRE_REPNZ | #DISTORM_INST_PRE_REP
#DISTORM_INST_PRE_LOKREP_MASK = #DISTORM_INST_PRE_LOCK | #DISTORM_INST_PRE_REPNZ | #DISTORM_INST_PRE_REP
#DISTORM_INST_PRE_SEGOVRD_MASK32 = #DISTORM_INST_PRE_CS | #DISTORM_INST_PRE_SS | #DISTORM_INST_PRE_DS | #DISTORM_INST_PRE_ES
#DISTORM_INST_PRE_SEGOVRD_MASK64 = #DISTORM_INST_PRE_FS | #DISTORM_INST_PRE_GS
#DISTORM_INST_PRE_SEGOVRD_MASK = #DISTORM_INST_PRE_SEGOVRD_MASK32 | #DISTORM_INST_PRE_SEGOVRD_MASK64



; Extended flags for VEX:
; Indicates that the instruction might have VEX.L encoded.
#DISTORM_INST_VEX_L = 1
; Indicates that the instruction might have VEX.W encoded.
#DISTORM_INST_VEX_W = 1 << 1
; Indicates that the mnemonic of the instruction is based on the VEX.W bit.
#DISTORM_INST_MNEMONIC_VEXW_BASED = 1 << 2
; Indicates that the mnemonic of the instruction is based on the VEX.L bit.
#DISTORM_INST_MNEMONIC_VEXL_BASED = 1 << 3
; Forces the instruction to be encoded with VEX.L, otherwise it's undefined.
#DISTORM_INST_FORCE_VEXL = 1 << 4

; Indicates that the instruction is based on the MOD field of the ModRM byte.
; (MOD==11: got the right instruction, Else skip +4 in prefixed table For the correct instruction).

#DISTORM_INST_MODRR_BASED = 1 << 5
; Indicates that the instruction doesn't use the VVVV field of the VEX prefix, if it does then it's undecodable.
#DISTORM_INST_VEX_V_UNUSED = 1 << 6

; Indication that the instruction is privileged (Ring 0), this should be checked on the opcodeId field.
#DISTORM_OPCODE_ID_PRIVILEGED = $8000


;Indicates which operand is being decoded.
; Destination (1st), Source (2nd), op3 (3rd), op4 (4th).
; Used To set the operands' fields in the _DInst structure!


; _OperandNumberType
Enumeration
  #DISTORM_ONT_NONE = -1
  #DISTORM_ONT_1 = 0
  #DISTORM_ONT_2 = 1
  #DISTORM_ONT_3 = 2
  #DISTORM_ONT_4 = 3
EndEnumeration

; CPU Flags that instructions modify, test or undefine, in compacted form (CF,PF,AF,ZF,SF are 1:1 map to EFLAGS).
#DISTORM_D_COMPACT_CF = 1		; Carry
#DISTORM_D_COMPACT_PF = 4		; Parity
#DISTORM_D_COMPACT_AF = $10	; Auxiliary
#DISTORM_D_COMPACT_ZF = $40	; Zero
#DISTORM_D_COMPACT_SF = $80	; Sign
; The following flags have to be translated to EFLAGS.
#DISTORM_D_COMPACT_IF = 2		; Interrupt
#DISTORM_D_COMPACT_DF = 8		; Direction
#DISTORM_D_COMPACT_OF = $20	; Overflow

; The mask of flags that are already compatible with EFLAGS.
#DISTORM_D_COMPACT_SAME_FLAGS = #DISTORM_D_COMPACT_CF | #DISTORM_D_COMPACT_PF | #DISTORM_D_COMPACT_AF | #DISTORM_D_COMPACT_ZF | #DISTORM_D_COMPACT_SF



;  * In order To save more space For storing the DB statically,
;  * I came up With another level of Shared info.
;  * Because I saw that most of the information that instructions use repeats itself.
;  *
;  * Info about the instruction, source/dest types, meta And flags.
;  * _InstInfo points To a table of _InstSharedInfo.

Structure _DISTORM_InstSharedInfo Align #PB_Structure_AlignC
  flagsIndex.a ; An index into FlagsTables
  s.a          ; OpType.
  d.a
  meta.a ; Hi 5 bits = Instruction set class | Lo 3 bits = flow control flags.
  
  ; * The following are CPU flag masks that the instruction changes.
  ; * The flags are compacted so 8 bits representation is enough.
  ; * They will be expanded in Runtime To be compatible To EFLAGS.
  
  modifiedFlagsMask.a
  testedFlagsMask.a
  undefinedFlagsMask.a
EndStructure

Structure _DISTORM_InstSharedInfo_array
  InstSharedInfo._DISTORM_InstSharedInfo[0]
EndStructure

; This Structure is used For the instructions DB And Not For the disassembled result code!
; This is the BASE Structure, there are extensions To this Structure below.

Structure _DISTORM_InstInfo Align #PB_Structure_AlignC
  sharedIndex.u ; An index into the SharedInfoTable.
  opcodeId.u ; The opcodeId is really a byte-offset into the mnemonics table. MSB is a privileged indication.
EndStructure

Structure _DISTORM_InstInfo_array
  InstInfo._DISTORM_InstInfo[0]
EndStructure

; * There are merely few instructions which need a second mnemonic For 32 bits.
; * Or a third For 64 bits. Therefore sometimes the second mnemonic is empty but Not the third.
; * In all decoding modes the first mnemonic is the Default.
; * A flag will indicate it uses another mnemonic.
; *
; * There are a couple of (SSE4) instructions in the whole DB which need both op3 And 3rd mnemonic For 64bits,
; * therefore, I decided To make the extended Structure contain all extra info in the same Structure.
; * There are a few instructions (SHLD/SHRD/IMUL And SSE too) which use third operand (Or a fourth).
; * A flag will indicate it uses a third/fourth operand.

Structure _DISTORM_InstInfoEx Align #PB_Structure_AlignC
  ; Base structure (doesn't get accessed directly from code).
  BASE._DISTORM_InstInfo
  
  ; Extended starts here. 
  flagsEx.a ; 8 bits are enough, in the future we might make it a bigger integer. 
  op3.a ;  OpType.
  op4.a
  opcodeId2.u
  opcodeId3.u
EndStructure

Structure _DISTORM_InstInfoEx_array
  InstInfoEx._DISTORM_InstInfoEx[0]
EndStructure

; Trie data structure node type: 

; _InstNodeType
Enumeration
	#DISTORM_INT_NOTEXISTS = 0  ; Not exists.
	#DISTORM_INT_INFO = 1       ; It's an instruction info.
	#DISTORM_INT_INFOEX
	#DISTORM_INT_LIST_GROUP
	#DISTORM_INT_LIST_FULL
	#DISTORM_INT_LIST_DIVIDED
	#DISTORM_INT_LIST_PREFIXED
EndEnumeration

; Used to check instType < INT_INFOS, means we got an inst-info. Cause it has to be only one of them.
#DISTORM_INT_INFOS = #DISTORM_INT_LIST_GROUP

; Instruction node is treated as { int index:13;  int type:3; } 
; typedef uint16_t _InstNode;

CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  ImportC #DISTORM_LIB_FULLPATH
CompilerElse
  Import #DISTORM_LIB_FULLPATH
CompilerEndIf
  
  inst_lookup.i(*ci._DISTORM_CodeInfo, *ps._DISTORM_PrefixState)
  inst_lookup_3dnow.i(*ci._DISTORM_CodeInfo)
  
EndImport



;- =====================================
;- insts
;- =====================================


CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  ImportC #DISTORM_LIB_FULLPATH
CompilerElse
  Import #DISTORM_LIB_FULLPATH
  CompilerEndIf
  
  ; Flags Table
  FlagsTable()
  
  ; Root Trie DB
  InstSharedInfoTable()
  InstInfos()
  InstInfosEx()
  InstructionsTree()
  
  ; 3DNow! Trie DB
  Table_0F_0F()
  ; AVX related:
  Table_0F()
  Table_0F_38()
  Table_0F_3A()
  
  
  ;  * The inst_lookup will Return on of these two instructions according To the specified decoding mode.
  ;  * ARPL Or MOVSXD on 64 bits is one byte instruction at index 0x63.
  
  II_ARPL()
  II_MOVSXD()
  
  
  ;  * The NOP instruction can be prefixed by REX in 64bits, therefore we have To decide in Runtime whether it's an XCHG or NOP instruction.
  ;  * If 0x90 is prefixed by a useable REX it will become XCHG, otherwise it will become a NOP.
  ;  * Also note that If it's prefixed by 0xf3, it becomes a Pause.
  
  II_NOP()
  II_PAUSE()
  
  
  ;  * Used For letting the extract operand know the type of operands without knowing the
  ;  * instruction itself yet, because of the way those instructions work.
  ;  * See function instructions.c!inst_lookup_3dnow.
  
  II_3DNOW()
  
  ; Helper tables for pesudo compare mnemonics.
  CmpMnemonicOffsets()   ; SSE
  VCmpMnemonicOffsets()  ; AVX
  
EndImport



;- =====================================
;- operands
;- =====================================

CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
  ImportC #DISTORM_LIB_FULLPATH
CompilerElse
  Import #DISTORM_LIB_FULLPATH
  CompilerEndIf
  
  _REGISTERTORCLASS()
  
  operands_extract.l(*ci._DISTORM_CodeInfo, *di._DISTORM_DInst, *ii._DISTORM_InstInfo, 
                     instFlags.l, type.l, opNum.l, modrm.l, *ps._DISTORM_PrefixState, effOpSz.l,
                     effAdrSz.l, *lockableInstruction.LONG)
  
EndImport


;- =====================================
;- x86defs
;- =====================================



#DISTORM_SEG_REGS_MAX = 6
#DISTORM_CREGS_MAX = 9
#DISTORM_DREGS_MAX = 8

; Maximum instruction size, including prefixes
#DISTORM_INST_MAXIMUM_SIZE = 15

; Maximum range of imm8 (comparison type) of special SSE CMP instructions.
#DISTORM_INST_CMP_MAX_RANGE = 8

; Maximum range of imm8 (comparison type) of special AVX VCMP instructions.
#DISTORM_INST_VCMP_MAX_RANGE = 32

; Wait instruction byte code.
#DISTORM_INST_WAIT_INDEX = $9b

; Lea instruction byte code.
#DISTORM_INST_LEA_INDEX = $8d

; NOP/XCHG instruction byte code.
#DISTORM_INST_NOP_INDEX = $90

; ARPL/MOVSXD instruction byte code.
#DISTORM_INST_ARPL_INDEX = $63

; Minimal MODR/M value of divided instructions.
; It's $c0, two MSBs set, which indicates a general purpose register is used too.

#DISTORM_INST_DIVIDED_MODRM = $c0

; This is the escape byte value used for 3DNow! instructions.
#DISTORM__3DNOW_ESCAPE_BYTE = $0f

#DISTORM_PREFIX_LOCK = $f0
#DISTORM_PREFIX_REPNZ = $f2
#DISTORM_PREFIX_REP = $f3
#DISTORM_PREFIX_CS = $2e
#DISTORM_PREFIX_SS = $36
#DISTORM_PREFIX_DS = $3e
#DISTORM_PREFIX_ES = $26
#DISTORM_PREFIX_FS = $64
#DISTORM_PREFIX_GS = $65
#DISTORM_PREFIX_OP_SIZE = $66
#DISTORM_PREFIX_ADDR_SIZE = $67
#DISTORM_PREFIX_VEX2b = $c5
#DISTORM_PREFIX_VEX3b = $c4

; REX prefix value range, 64 bits mode decoding only.
#DISTORM_PREFIX_REX_LOW = $40
#DISTORM_PREFIX_REX_HI = $4f
; In order to use the extended GPR's we have to add 8 to the Modr/M info values.
#DISTORM_EX_GPR_BASE = 8

; Mask for REX and VEX features:
; Base
#DISTORM_PREFIX_EX_B = 1
; Index
#DISTORM_PREFIX_EX_X = 2
; Register
#DISTORM_PREFIX_EX_R = 4
; Operand Width
#DISTORM_PREFIX_EX_W = 8
; Vector Lengh
#DISTORM_PREFIX_EX_L = $10





CompilerEndIf
