
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


#saveFileDlg = QtWidgets.QFileDialog()
#saveFileDlg.setWindowTitle("Weee")
#saveFileDlg.show()

SEGMENTS_TO_IGNORE=[ ".plt", ".plt.got", "extern" ]

def findSegmentsToIgnore():
   retVal = []
   segStart = get_first_seg()
   while(segStart != BADADDR):
      segEnd = get_segm_end(segStart)

      segName = get_segm_name(segStart)

      if (segName in SEGMENTS_TO_IGNORE):      
         print("Ignoring segment {} - {} = {}".format(hex(segStart), hex(segEnd), segName))
         retVal.append( (segStart, segEnd) )
      else:
         print("Keeping segment {} - {} = {}".format(hex(segStart), hex(segEnd), segName))

      segStart = get_next_seg(segStart)

   print("Done searching for segments")
   return retVal

def pruneFunctionsFromSegmentsIgnore(functionList, segmentIgnoreList):
   retFuncList = []
   print("Starting pruneFunctionsFromSegmentsIgnore")
   
   for curFunction in functionList:
      eliminate = False
      for curSegment in segmentIgnoreList:
         funcAddress = curFunction[0]
         if ( (funcAddress >= curSegment[0]) and (funcAddress <= curSegment[1]) ):
	    print("Eliminating function {} @ {}".format(curFunction[1], hex(funcAddress)))
	    eliminate = True
      
      if not eliminate:
         retFuncList.append(curFunction)

   print("Done eliminating functions")
   return retFuncList

def getFunctionComments(functionList):
   """
   Returns a tuple containing 2 lists. Repeatable comment list and non-repeatable comment list.
   Each comment is a tuple with the address, and the comment text
   """

   repeatableComments = []
   nonRepeatableComments = []

   for singleFunc in functionList:
      funcAddress = singleFunc[0]
      funcName = singleFunc[1]

      funcComment = get_func_cmt(funcAddress, 0)
      funcCommentRepeatable = get_func_cmt(funcAddress, 1)

      if ( (len(funcComment) == 0) and (len(funcCommentRepeatable) == 0) ):
         print("No comments for function {}".format(funcName))
      else:
         if (len(funcComment) != 0):
            print("Function {} has nr_cmt={}".format(funcName, funcComment))
            nonRepeatableComments.append( (funcAddress, funcComment) )

	 if (len(funcCommentRepeatable) != 0):
            print("Function {} has rep_cmt={}".format(funcName, funcCommentRepeatable))
	    repeatableComments.append( (funcAddress, funcCommentRepeatable) ) 

   return (repeatableComments, nonRepeatableComments)   

def getFuncCommentText(address, cmtList):
   for singleCmt in cmtList:
      cmtAddr = singleCmt[0]
      cmtText = singleCmt[1]

      if (address == cmtAddr):
         return cmtText

   # if we get here, we didn't find the function address in the list
   return ""

def script_main():
   saveFileName = QtWidgets.QFileDialog.getSaveFileName(None, "Pick an export file")
   # saveFileName = ( "test.txt", "")

   if (saveFileName[0] == ""):
      print("User did not pick an export file, user canceled")
      return

   saveFileNameStr = str(saveFileName[0])
   print("User selected {} as export file".format(saveFileNameStr))

   outputFile = QtCore.QFile(saveFileNameStr)

   flist = getUserNamedFunctions()
   ignoreSegs = findSegmentsToIgnore()
   (funcCmts, nrFuncCmts) = getFunctionComments(flist)

   print("Bad segments = {}".format(ignoreSegs))
   print("Function list = {}".format(flist))

   flist = pruneFunctionsFromSegmentsIgnore(flist, ignoreSegs)

   print("Function list = {}".format(flist))
   
   outputFile.open(QtCore.QIODevice.WriteOnly | QtCore.QIODevice.Truncate)

   for f in flist:
      fAddr = f[0]
      fName = f[1]
      outputFile.write("FUNC={},{}\n".format(hex(fAddr), fName))

      fCmt = getFuncCommentText(fAddr, funcCmts)
      if (len(fCmt) > 0):
         outputFile.write("FUNC_CMT={},{}\n".format(hex(fAddr), fCmt))

      fCmtNr = getFuncCommentText(fAddr, nrFuncCmts)
      if (len(fCmtNr) > 0):
         outputFile.write("FUNC_CMT_NR={},{}\n".format(hex(fAddr), fCmtNr))

   outputFile.close()


def getUserNamedFunctions():
   """
   Returns a list of function address and function name tuples
   """

   faddr = idc.get_next_func(0);
   retData = []

   while(faddr != BADADDR):
      #print("Addr = {}".format(hex(faddr)))
      nextAddr = idc.next_not_tail(faddr)

      fname = idc.get_func_name(faddr)
      
      if (fname.startswith("sub_")):
         faddr = idc.get_next_func(nextAddr)
	 continue

      print("Found a user named function @ {}: {}".format(hex(faddr), fname))
      retData.append( (faddr, fname) )
      
      faddr = idc.get_next_func(nextAddr)

   print("Done searching for functions")
   return retData

def analyzeCode():
   faddr = idc.get_next_func(0)
   while(faddr != BADADDR):
      fname = idc.get_func_name(faddr)

      fnonrepeatcmt = idc.get_func_cmt(faddr, 0)
      frepeatcmt = idc.get_func_cmt(faddr, 1)
      print("Function comment repeatable {} and non-repeatable".format(frepeatcmt, fnonrepeatcmt))

      # We need to find the end of the function
      fendaddr = faddr
      nextAddr = faddr
      while(func_contains(faddr, nextAddr)):
         fendaddr = nextAddr
      nextAddr = next_not_tail(nextAddr)
   

      # prev_not_tail <- next displayable address
   
      #print("Function @ {} = {}".format(hex(faddr), fname))
      
      print("Looking for comments for {} from {} to {}".format(fname, hex(faddr), hex(fendaddr)))
      cmtAddr = faddr
      while( cmtAddr < fendaddr):
         cmtText = idc.get_cmt(cmtAddr, 1)
         if cmtText != None:
            print("Function @ {} = {}".format(hex(faddr), fname))
         print("Comment @ {} = {}".format(hex(cmtAddr), cmtText))
         cmtAddr = idc.next_not_tail(cmtAddr)


      faddr = idc.get_next_func(faddr)


script_main()
