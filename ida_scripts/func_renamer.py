
# I'm trying to create a program that will look for unnamed functions in a binary, and then see if
# they can be named using a trace debug statements included in the binary that used the a
# function name macro for tracing program execution

# I've run into a roadblock that was unforseen though

# I can identify un-named functions
# I can get the disassembly of each line of code from withing the function
# I can probably figure out what the call to DEBUG_TRACE is in the function
# How to determine the args?
  # X86 code that uses the stack, what could i do?
  # ARM x86_64 pretty easy since they pass args via registers
# All of the above relies on the poor idea that the functions are all linear execution without 
#   branching and gotos within the function, but this probably OK most of the time, who would
#   branch right into arg population of a trace statement? 
# Have no way to figure out the contents of the parameter register contents.  Hex-rays decompiler
#   figures this out, but I don't know how easy to do in assembly.  Gets even messier on ARM due
#   to possible crazy addressing modes and what not

def analyzeSingleFunction(startAddr, endAddr):
  print("Function Name: " + GetFunctionName(startAddr))
  
  curAddr = startAddr
  while(curAddr < endAddr):
  
    print(GetDisasm(curAddr))
    #print("Item size: ", ItemSize(startAddr))
    curAddr += ItemSize(curAddr)
    
    
  print("End of analysis")




funcStartAddr = 0
while (funcStartAddr != 0xffffffff):

  funcStartAddr = NextFunction(funcStartAddr)
  funcEndAddr = FindFuncEnd(funcStartAddr)
  funcName = GetFunctionName(funcStartAddr)
  
  #print ("Func start: ", hex(funcStartAddr), " and ends ", hex(func_end_addr), "name=", funcName)
  
  if (funcName.startswith("sub_")):
    analyzeSingleFunction(funcStartAddr, funcEndAddr) 
