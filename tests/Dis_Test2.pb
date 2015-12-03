XIncludeFile #PB_Compiler_FilePath + "TestHelper.pbi"

Procedure myTestFunc(a.l, b.l)
  a = 8
  b = 4
  Protected myvalue.q = 9999999999999999999
  ProcedureReturn 2
EndProcedure

Procedure Do_Distorm_Test2()
  Protected res.l
  Protected decodedInstructionsCount.l = 0
  Protected i.l = 0
  Protected offset.q = 0
  Protected max_instructions.l = 1000
  
  Protected Dim decodedInstructions._DISTORM_DecodedInst(0)
  Protected Dim Instructions._DISTORM_DInst(max_instructions)
  
  Protected code_info._DISTORM_CodeInfo
  
  offset = 0
  
  code_info\codeOffset = offset
  code_info\code = @myTestFunc()
  code_info\codeLen = 500
  code_info\dt = DISTORM_M_GET_DECODEMODE_PB()
  code_info\features = #DISTORM_DF_STOP_ON_RET
  
  PrintN("Decoding Instructions form: "+Hex(@myTestFunc()))
  
  res = distorm_decompose64(@code_info, @Instructions(), max_instructions, @decodedInstructionsCount)
  
  If res = #DISTORM_DECRES_SUCCESS
    PrintN("Decoded "+Str(decodedInstructionsCount)+" Instructions")
    PrintN("")
    
    Protected x.l = 0
    
    For i.l = 0 To decodedInstructionsCount - 1
      distorm_format64(@code_info, @Instructions(i), @decodedInstructions(x))
      
      ReDim decodedInstructions(ArraySize(decodedInstructions())+1)
      x + 1
    Next i
    

    Protected de_text.s = ""
    
    For i.l = 0 To decodedInstructionsCount - 1
      de_text = Distorm_InstructionString(@decodedInstructions(i))
      PrintN(de_text)
    Next i
    
  Else
    PrintN("Decoding Failed")
  EndIf
  


EndProcedure

If OpenConsole()
  PrintN("diStorm version: "+GetDistormVersionString())
  PrintN("")
  
  Do_Distorm_Test2()
  
  PrintN("")
  PrintN("Press enter to continue")
  PrintN("")
  Input()
  
  CloseConsole()
EndIf
