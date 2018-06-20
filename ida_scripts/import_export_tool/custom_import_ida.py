
# Things I need to work on to export a proper IDA database
# Functions
#    Does the function have comments?
#    Get all the of the function line comments
#    Get the function (summary) comment -get_func_cmt
#    Function arg types
# External comments
# Global variable names - get_type
# Structures - get_struck_by_idx, get_struc_id, get_struc_id, get_struc_idx, get_struc_name, get_struc_size
#    All of the field / types - get_member_id, get_member_name, get_member_size, get_member_strid
#    Global variables that use the structures
#    Member comments - get_member_cmt
# Enumeration
#    Enumeration comments
# Arrays? - make_array

# For redoing the export on new idb:
# SetType(ea, type)
# add_struc(index, name, is_union)


# Format of the output file (implemented)
# FUNC=start_address,func_name
# FUNC_ARG=0,name,type
# FUNC_CMT=addr,cmt
# FUNC_CMT_NR=addr,cmt

# Format of the output file (planned, not implemented)
# CMT=0,cmt
# FUNC_ARG=0,name,type



# todo - need to not get the extern functions
# segment related idac functions:  get_first_seg(), get_next_seg(ea), get_segm_attr(), get_segm_end(ea), get_segm_name(ea), 
from PyQt5 import QtCore, QtGui, QtWidgets


def log(text, lineNum):
   print("[Line {}] {}".format(lineNum, text))


def convertToInt(text):
   text = text.strip()

   # Many of the python strings have an L at the end, which is stupid
   text = text.replace("L", "")

   if (text.startswith("0x")):
      # do a hex conversion
      return int(text[2:], 16)
   else:
      return int(text)

def idaDefaultName(prefixText, address):
   addrStr = hex(address)
   if (addrStr.startswith("0x")):
      addrStr = addrStr[2:]

   return prefixText + addrStr.upper()


gForceAll = False
gForceOverwrite = False
def askUserToOverwrite(questionToAsk):
   global gForceAll
   global gForceOverwrite

   if gForceAll:
      return gForceOverwrite

   msgBoxChoices = QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No | QtWidgets.QMessageBox.YesToAll | QtWidgets.QMessageBox.NoToAll
   userChoice = QtWidgets.QMessageBox.question(None, "Overwrite existing name?", questionToAsk, msgBoxChoices)

   if userChoice == QtWidgets.QMessageBox.YesToAll:
      gForceAll = True
      gForceOverwrite = True
      userChoice = QtWidgets.QMessageBox.Yes
   elif userChoice == QtWidgets.QMessageBox.NoToAll:
      gForceAll = True
      gForceOverwrite = False
      userChoice = QtWidgets.QMessageBox.No

   return (userChoice == QtWidgets.QMessageBox.Yes)



def functionCommentInstruction(cmdArgs, repeatableCmt, lineNum):
   commaPos = cmdArgs.find(",")
   if (commaPos == -1):
      log("function comment instruction missing arguments", lineNum)
      return

   addr = convertToInt(cmdArgs[0:commaPos])
   cmtText = cmdArgs[commaPos+1:]

   if (repeatableCmt):
      rptOption = 1
   else:
      rptOption = 2

   currentComment = get_cmt(addr, rptOption)

   if (currentComment == cmtText):
      log("Address {} already has correct comment: {}".format(hex(addr), cmtText), lineNum)
      return

   if (currentComment != None and len(currentComment) > 0):
      # Possible conflict, ask user what to do
      question = "Should we overwrite comment ({}) at address {} with new comment: {}".format(
         currentComment, hex(addr), cmtText)
      override = askUserToOverwrite(question)

      if (override):
         set_cmt(addr, cmtText, rptOption)
	 log("Address {}, wrote comment: {}".format(hex(addr), cmtText), lineNum)
      else:
         log("User choose to keep comment at address {}".format(hex(addr)), lineNum)
   else:
      # No confict here!
      set_func_cmt(addr, cmtText, rptOption)
      log("Address {}, wrote comment: {}".format(hex(addr), cmtText), lineNum)
      

def funcArgInstruction(text, lineNum):
   log("funcArg {} [IMPORT FUNCTIONALITY NOT IMPLEMENTED]".format(text), lineNum)

def nameFunction(addr, name, lineNum):
   # We can safely overwrite the default IDA names
   success = set_name(addr, name)

   if (success == 1):
      log("Renamed address {} to {}".format(addr, name), lineNum)
   else:
      log("Failed to rename address {} to {}".format(addr, name), lineNum)
   return
 

def funcInstruction(text, lineNum):
   """
   # FUNC=start_address,func_name
   """
   print("funcInstruction start")

   argList = text.split(",")
   if (len(argList) < 2):
      log("FUNC instruction missing arguments", lineNum)
      return

   startAddr = convertToInt(argList[0])
   funcName = argList[1]

   oldFuncName = get_func_name(startAddr)
   if (oldFuncName == ""):
      log("FUNC instruction for address {} ({}), but there is no function at that address".format(
         hex(startAddr), funcName), lineNum)
      return

   if (oldFuncName == funcName):
      log("Function {} already named {}".format(oldFuncName, funcName), lineNum)
      return

   defaultName = idaDefaultName("sub_", startAddr)
   if (oldFuncName == defaultName):
      nameFunction(startAddr, funcName, lineNum)
      return
      
   userChoice = askUserToOverwrite("Should we name {} to {}".format(oldFuncName, funcName))
   if (userChoice):
      nameFunction(startAddr, funcName, lineNum)
   else:
      log("User doesn't want to name address {} to {} from {}".format(startAddr, funcName, oldFuncName), lineNum)


def processImportInstruction(instruction, lineNum):
   instruction = instruction.strip()

   if (instruction.startswith("#")):
      # Comments line, ignore
      return

   # The '=' sign seperates the instruction from the arguments
   delimiter = instruction.find("=")
   if (delimiter == -1):
      print("Error processing the following line because there was no '=' delimiter found on line {}".format(lineNum))
      print(instruction)
      return
   
   cmdText = instruction[0:delimiter]
   cmdArgs = instruction[delimiter+1:]

   print("Processing line {}, command={}, args={}".format(lineNum, cmdText, cmdArgs))

   if (cmdText == "FUNC"):
      funcInstruction(cmdArgs, lineNum)
   elif (cmdText == "FUNC_ARG"):
      funcArgInstruction(cmdArgs, lineNum)
   elif (cmdText == "FUNC_CMT_NR"):
      functionCommentInstruction(cmdArgs, False, lineNum)
   elif (cmdText == "FUNC_CMT"):
      functionCommentInstruction(cmdArgs, True, lineNum)

      
# Not implemented
# FUNC_ARG=funcAddr,argNumber,name,type

# Is implemented
# FUNC=start_address,func_name
# FUNC_CMT=addr,cmt
# FUNC_CMT_NR=addr,cmt



def script_main():
   openFileName = QtWidgets.QFileDialog.getOpenFileName(None, "Pick an export file to load")
   # openFileName = ( "test.txt", "")

   if (openFileName[0] == ""):
      print("User did not pick an file to import, user canceled")
      return

   openFileNameStr = str(openFileName[0])

   print("User selected {} as import file".format(openFileNameStr))

   # Seems like it will be easiest to use the python file API to read the file in
   lineNum = 1
   with open(openFileNameStr, 'rb') as inputFile:
      try:
         for singleLine in inputFile:
	    processImportInstruction(singleLine, lineNum)
            lineNum += 1
      except IOError:
         print("Error while reading the import file")
   


script_main()
