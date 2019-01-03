from PyQt5 import QtCore, QtGui, QtWidgets

# Todo: what if user cancels on the dialogs?
# Add some documentation

def dumpData():

   addr = get_screen_ea()
   if (addr == BADADDR):
      addressText = "0x00000000"
   else:
      addressText = hex(addr)
      addressText = addressText.replace("L","")
   
   userStart = QtWidgets.QInputDialog.getText(None, "Start Address", 
                                              "Enter the address to start dumping\n"
                                              "Base 10 (default) or Base 16 with 0x prefix",
                                              text=addressText)

   userSize = QtWidgets.QInputDialog.getText(None, "Dump Size",
                                             "Enter the amount of data to dump\n"
                                             "Base 10 (default) or Base 16 with 0x prefix",
                                             text="0x400");

   if (userStart[0].startswith("0x")):
      startAddr = int(userStart[0][2:], 16)
   else:
      startAddr = int(userStart[0])

   if (userSize[0].startswith("0x")):
      size = int(userSize[0][2:], 16)
   else:
      size = int(userSize[0])

   endAddr = startAddr + size
   msg("Dumping {} bytes ({} to {})\n".format(hex(size), hex(startAddr), hex(endAddr)))

   suggestedFilename = "data_" + hex(startAddr) + "_" + hex(endAddr)

   saveName = QtWidgets.QFileDialog.getSaveFileName(None, "Select dump filename", suggestedFilename)

   if (saveName[0] == ""):
      msg("No filename selected, exitting\n")
      return

   binData = GetManyBytes(startAddr, endAddr - startAddr, 0)

   msg("Saving {} bytes to {}\n".format(endAddr - startAddr, saveName[0]))

   f = open(saveName[0], "w")
   f.write(binData)
   f.close()



dumpData()





