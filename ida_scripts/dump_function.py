from PyQt5 import QtCore, QtGui, QtWidgets

def dumpFunction(funcName):
   msg("Dumping function: {}\n".format(funcName))

   startAddr = get_name_ea_simple(funcName)

   endAddr = find_func_end(startAddr)

   msg("Function address = {} to {}\n".format(hex(startAddr), hex(endAddr)))
   suggestedFilename = funcName + "_" + hex(startAddr) + "_" + hex(endAddr)

   saveName = QtWidgets.QFileDialog.getSaveFileName(None, "Select dump filename", suggestedFilename)

   if (saveName[0] == ""):
      msg("No filename selected, exitting\n")
      return

   binData = GetManyBytes(startAddr, endAddr - startAddr, 0)

   msg("Saving {} bytes to {}\n".format(endAddr - startAddr, saveName[0]))

   f = open(saveName[0], "w")
   f.write(binData)
   f.close()

curAddr = get_screen_ea()

funcName = ""
if (curAddr == BADADDR):
   msg_box("No function selected\n")
else:
   funcName = get_func_name(curAddr)

if (funcName == ""):
   # User didn't highlight a function already, let them choose one from dialog
   funcAddr = choose_func("Choose a function to dump")
   funcName = get_func_name(funcAddr)


if (funcName != ""):
   dumpFunction(funcName)   






