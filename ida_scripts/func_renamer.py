
# I'm trying to create a program that will look for unnamed functions in a binary, and then see if
# they can be named using a trace debug statements included in the binary that used the a
# function name macro for tracing program execution

# To Do List
# - Need to see if discovered function name already exists in the IDA DB
# - If names already exists, try func_name1, func_name2, etc
# - Perform the rename
# - Create a dialog that allows user to type in log trace function name and parameter number
# - Create a dialog that ouptuts the results / discovery
# - Create a dialog with table and checkbox so user can decide which names to implement on function by function basis

import ida_hexrays

from PyQt5 import QtCore, QtGui, QtWidgets

def analyzeSingleArg(argText):
  # If the arg is quoted, it's a literal string, done!
  if (argText.find('"') != -1):
    # We found quotes, strip them off and return
    return argText.strip('"')

  # If it is an unknown variable, can we get the GetString(ea)
  if (argText.startswith("&unk_")):
    unkAddrText = argText[5:]
    unkAddrHex = int(unkAddrText, 16)
    print("Decoding param ", unkAddrText, " to ", unkAddrHex)

    fName = GetString(unkAddrHex)
    print("Var value = ", fName)
    # Lookup the symbol and try to figure out what it is

    #print("Type of label: ", IsString(argText))
    return fName

  else:
    return ""


def analyzeSingleCall(lineOfC, paramIndex):
  beginParen = lineOfC.find("(")
  endParen   = lineOfC.rfind(")")

  if ((beginParen == -1) or (endParen == -1)):
    print("Invalid function call format")
    #print("Begin@", beginParen, " End@", endParen)
    return ""
  else:
    argList = lineOfC[beginParen + 1:endParen].split(",")
    print argList

    if (len(argList) > paramIndex):
      singleArg = argList[paramIndex]
      print "Single Arg:" + singleArg
      return analyzeSingleArg(singleArg.strip())



def analyzeSingleFunction(startAddr, endAddr, searchString, paramIndex):
  print("Function Name: " + GetFunctionName(startAddr))

  curAddr = startAddr
  #while(curAddr < endAddr):

    #print(GetDisasm(curAddr))
    #print("Item size: ", ItemSize(startAddr))
    #curAddr += ItemSize(curAddr)


  #print("End of analysis")
  possibleNameList = dict()

  c = ida_hexrays.decompile(startAddr)
  for singleLine in str(c).split("\n"):
    leftJustifiedLine = singleLine.lstrip()
    if (leftJustifiedLine.startswith(searchString + "(")):
      print leftJustifiedLine
      possibleName = analyzeSingleCall(leftJustifiedLine, paramIndex)

      if possibleName in possibleNameList:
        possibleNameList[possibleName] = possibleNameList[possibleName] + 1
      else:
        possibleNameList[possibleName] = 1

  print("All possible function names: ", possibleNameList)

  if (len(possibleNameList) == 0):
    return ""

  numUses = 0
  for fName in possibleNameList:
    if (possibleNameList[fName] > numUses):
      numUses = possibleNameList[fName]
      retVal = fName

  return fName



discoveredNames = []
funcStartAddr = 0
while (funcStartAddr != 0xffffffff):

  funcStartAddr = NextFunction(funcStartAddr)
  funcEndAddr = FindFuncEnd(funcStartAddr)
  funcName = GetFunctionName(funcStartAddr)

  searchString = "NsLog"
  paramIndex = 2

  #print ("Func start: ", hex(funcStartAddr), " and ends ", hex(func_end_addr), "name=", funcName)

  if (funcName.startswith("sub_")):
    suggestedName = analyzeSingleFunction(funcStartAddr, funcEndAddr, searchString, paramIndex)

    if (suggestedName != ""):
      discoveredNames.append(suggestedName)

#mb = QtWidgets.QMessageBox()
#mb.setText("Done!")
#mb.setDetailedText(str(discoveredNames)
#mb.setModal(True)
#mb.show()

print("Done.  Discoverd: ", str(discoveredNames))
