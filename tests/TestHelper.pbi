XIncludeFile #PB_Compiler_FilePath + "..\distorm_lib.pbi"

EnableExplicit

Procedure.s Distorm_InstructionString(*Inst._DISTORM_DecodedInst)
  Protected result.s
  Protected str_instructionHex.s, str_mnemonic.s, str_operands.s
  Protected formated_instructionHex.s
  
  str_instructionHex = PeekS(@*Inst\instructionHex\p, -1, #PB_Ascii)
  str_mnemonic = PeekS(@*Inst\mnemonic\p, -1, #PB_Ascii)
  str_operands = PeekS(@*Inst\operands\p, -1, #PB_Ascii)
  
  If *Inst\instructionHex\length > 0
    Protected x.l 
    For x = 1 To Len(str_instructionHex) Step 2
      formated_instructionHex + UCase(Mid(str_instructionHex, x, 2)) + " "
    Next x
    
    formated_instructionHex = RTrim(formated_instructionHex)
  EndIf
  
  result = RSet(Hex(*Inst\offset),8, "0") + " (" + Str(*Inst\size) + ")"
  
  If *Inst\size >= 10
   result + " "
  Else
   result + "  "
  EndIf
  
  result + LSet(formated_instructionHex, 24)
  result + " " + str_mnemonic
  
  If *Inst\operands\length <> 0
    result + " "
  EndIf
  
  result + str_operands
  
  ProcedureReturn result    
EndProcedure

Procedure.s Distorm_CreateInstructionStringFromArray(Array Insts._DISTORM_DecodedInst(1), InstructionsCount.l)
  Protected result.s
  Protected i.l
  Protected inst_string.s
  Protected arr_size.i
  
  arr_size = ArraySize(Insts())
  
  If InstructionsCount > (arr_size+1)
    ProcedureReturn ""
  EndIf
  
  For i.l = 0 To InstructionsCount - 1
    inst_string = Distorm_InstructionString(@Insts(i))
    result + inst_string + #CRLF$
  Next i

  ProcedureReturn result
EndProcedure

Procedure.s Format_DistormVersion(dver.l)
  Protected result.s
  result = Str(dver >> 16)+"."+Str((dver >> 8) & $ff)+"."+Str(dver & $ff)
  ProcedureReturn result
EndProcedure

Procedure.s GetDistormVersionString()
  Protected result.s
  result = Format_DistormVersion(distorm_version())
  ProcedureReturn result
EndProcedure


