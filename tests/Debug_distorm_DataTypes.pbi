XIncludeFile #PB_Compiler_FilePath + "..\distorm_lib.pbi"

EnableExplicit

Macro M_DQUOTE
"
EndMacro

Macro M_OffsetOfEx(__structA__, __structB__)
  (OffsetOf(__structA__) + OffsetOf(__structB__))
EndMacro

Macro M_MAKE_GENERIC_VALUE(__NUMBER__)
  Str(__NUMBER__)+" | 0x"+Hex(__NUMBER__)
EndMacro

CompilerIf #PB_Compiler_Debugger
  
  Macro M_DEBUG_SIZEOF(__NAME__)
    Debug M_DQUOTE#__NAME__ - size (dec) = "+Str(SizeOf(__NAME__))+" | size (hex) = 0x"+Hex(SizeOf(__NAME__))
  EndMacro
  
  Macro M_DEBUG_OFFSETOF(__NAME__)
    Debug M_DQUOTE#__NAME__ - offset (dec) = "+Str(OffsetOf(__NAME__))+" | offset (hex) = 0x"+Hex(OffsetOf(__NAME__))
  EndMacro

CompilerElse
  
  Macro M_DEBUG_SIZEOF(__NAME__)
  EndMacro
  
  Macro M_DEBUG_OFFSETOF(__NAME__)
  EndMacro
  
CompilerEndIf

Debug "======== Displaying Structures Sizes  ========"

M_DEBUG_SIZEOF(_DISTORM_CodeInfo)
M_DEBUG_SIZEOF(_DISTORM_Value)
M_DEBUG_SIZEOF(_DISTORM_Operand)
M_DEBUG_SIZEOF(_DISTORM_DInst)
M_DEBUG_SIZEOF(_DISTORM_WString)
M_DEBUG_SIZEOF(_DISTORM_DecodedInst)

Debug "----- Mnemonics -----"

M_DEBUG_SIZEOF(_DISTORM_WMnemonic)
M_DEBUG_SIZEOF(_DISTORM_WRegister)


Debug "----- Prefix -----"

M_DEBUG_SIZEOF(_DISTORM_PrefixState)

Debug "----- Instructions -----"

M_DEBUG_SIZEOF(_DISTORM_InstSharedInfo)
M_DEBUG_SIZEOF(_DISTORM_InstInfo)
M_DEBUG_SIZEOF(_DISTORM_InstInfoEx)


Debug "Distorm Version: "+distorm_version()
