XIncludeFile #PB_Compiler_FilePath + "TestHelper.pbi"

Procedure Do_Distorm_Test1()
  Protected res.l
  Protected Dim decodedInstructions._DISTORM_DecodedInst(1000)
  Protected decodedInstructionsCount.l = 0
  Protected i.l = 0
  Protected offset.q = 0
  Protected max_instructions.l = 1000
  
  
  Protected *code = ?test_data1_start
  Protected codeLen.l = ?test_data1_end - ?test_data1_start
  
  res = distorm_decode64(offset, *code, codeLen, #DISTORM_Decode32Bits, @decodedInstructions(), max_instructions, @decodedInstructionsCount)
  
  PrintN("")
  
  If res = #DISTORM_DECRES_SUCCESS
    Protected de_text.s = ""
    
    For i.l = 0 To decodedInstructionsCount - 1
      de_text = Distorm_InstructionString(@decodedInstructions(i))
      
      PrintN(de_text)
      
    Next i
  Else
    PrintN("Decoding Failed")
  EndIf
  
 ;SetClipboardText( Distorm_CreateInstructionStringFromArray(decodedInstructions(), decodedInstructionsCount))
  
  DataSection
    test_data1_start: ; 11 bytes 
    Data.a $55, $8B, $EC, $8B, $45, $08, $03, $45, $0C, $C9, $C3
    test_data1_end: 
  EndDataSection

EndProcedure

If OpenConsole()
  PrintN("diStorm version: "+GetDistormVersionString())
  PrintN("")
  
  Do_Distorm_Test1()
  
  PrintN("")
  PrintN("Press enter to continue")
  PrintN("")
  Input()
  
  CloseConsole()
EndIf
