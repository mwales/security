# This script's purpose is to load a System.map file for a Linux kernel and name functions based
# on the names in the System.map file provided by the Linux kernel build process

# To run the script, from IDA, File->Load Script... and select this file.  You then need to select
# a kernel System.map file.  It will then ask user to provide the offset of the kernel address
# space from the address space in IDA.  All functions named sub_xxxx will be looked up in the map to 
# determine a different name for them.  Select all the functions you want renamed, then press OK to
# perform the renaming after the analysis is complete.

import ida_hexrays
import idaapi 
import sys

from PyQt5 import QtCore, QtGui, QtWidgets

# This class is copied directly from the func_renamer.py script
class RenameSelectionGui(object):
    def __init__(self):
        self.renameData = []


    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(655, 532)
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tableWidget = QtWidgets.QTableWidget(Dialog)
        self.tableWidget.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidget.setTabKeyNavigation(False)
        self.tableWidget.setDragDropOverwriteMode(False)
        self.tableWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidget.setRowCount(10)
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setHorizontalHeaderLabels(["Rename", "Address", "Current Name", "Suggested Name"])
        self.verticalLayout.addWidget(self.tableWidget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.pushButton = QtWidgets.QPushButton(Dialog)
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout.addWidget(self.pushButton)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.horizontalLayout.addWidget(self.buttonBox)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept)
        self.buttonBox.accepted.connect(self.okClicked)
        self.buttonBox.rejected.connect(Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

        self.pushButton.clicked.connect(self.invertAllClicked)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Rename Confirmation"))
        self.pushButton.setText(_translate("Dialog", "Invert All"))

    def addItem(self, address, curName, newName):
        rowInfo = []

        # store internally important stuff to process later
        cb = QtWidgets.QCheckBox()
        rowInfo.append(cb)
        rowInfo.append(address)
        rowInfo.append(newName)

        curRow = len(self.renameData)

        if (self.tableWidget.rowCount() == curRow):
            # Add a new row!
            self.tableWidget.setRowCount(curRow + 1)

        #print("Adding a row to the table at curRow = ", curRow)
        self.tableWidget.setCellWidget(curRow, 0, cb)
        self.tableWidget.setItem(curRow, 1, QtWidgets.QTableWidgetItem(hex(address)))
        self.tableWidget.setItem(curRow, 2, QtWidgets.QTableWidgetItem(curName))
        self.tableWidget.setItem(curRow, 3, QtWidgets.QTableWidgetItem(newName))

        self.renameData.append(rowInfo)

    def adjustColumnWidths(self):
        self.tableWidget.resizeColumnsToContents()

    def invertAll(self):
        print("Invert All!")

        for rowData in self.renameData:
            if (rowData[0].isChecked()):
                rowData[0].setChecked(False)
            else:
                rowData[0].setChecked(True)

    def renameFunctions(self):
        print("Renaming functions!")
        for rowData in self.renameData:
            if (rowData[0].isChecked()):
                print("Renaming ", rowData[1], " to ", rowData[2])
                MakeName(rowData[1], rowData[2])
        print("Renaming complete")

    # Qt Slots are called by the GUI
    def invertAllClicked(self):
        self.invertAll()

    def okClicked(self):
        self.renameFunctions()

# Prompt the user to pick a symbol file to load
def promptUserFile():
  symFileChooser = QtWidgets.QFileDialog()
  filterList = []
  filterList.append("Kernel Map File (*.map)")
  filterList.append("All Files (*)")
  symFileChooser.setNameFilters(filterList)
 
  symFileChooser.setFileMode(QtWidgets.QFileDialog.ExistingFile)

  symFileChooser.exec_()
 
  dialogResult = symFileChooser.result()
  print("Result = {}".format(dialogResult)) 
 
  if (dialogResult == QtWidgets.QDialog.Accepted): 
    mapFiles = symFileChooser.selectedFiles()
    return mapFiles
  else:
    print("User canceled")
    mapFiles = []
    return mapFiles

def readSymbolMapFile(filename):
  symMap = { }
  with open(filename) as symFile:
    for singleLine in symFile:
      # Each line of the symbol consists of address, code, symbol name
      symParts = singleLine.split()

      if (len(symParts) == 3):
        address = int(symParts[0], 16)
	symType = symParts[1]
	symName = symParts[2]

        if address in symMap:
	  # print("Address {} is already in symbol map: {} vs {}".format(hex(address), symMap[address], symName))
	  newSymName = deconflictKernelNames(symMap[address], symName)
	  symMap[address] = newSymName
	else:
	  symMap[address] = symName

  return symMap

# If an address already has a name, use this function to determine what a merged name should be
def deconflictKernelNames(nameA, nameB):
  # I often see names like __key.12345 in the symbol list, since these seem useless, they will
  # have no precedence and will always be replaced
  if "__key." in nameA:
    # print("{} is a useless name, using {} instead".format(nameA, nameB))
    return nameB
  if "__key." in nameB:
    # print("{} is a useless name, using {} instead".format(nameB, nameA))
    return nameA

  # Sometimes I will see slight difference in number of underscores or capitilization in what is
  # otherwise the same function name.  If this is the case, just keep the old name
  nameAReduced = nameA.replace("_", "").lower()
  nameBReduced = nameB.replace("_", "").lower()
  if (nameAReduced == nameBReduced):
    # print("{} and {} are essentially the same name, keeping {}".format(nameA, nameB, nameA))
    return nameA

  # We are left with merging the name together, but we are not going to merge names more than once
  # cause that will just be ridiculous
  if ("_or_" in nameA):
    # print("Not merging any more names into name {}".format(nameA))
    return nameA

  # These 2 names are very different, merge the names:  nameA_or_nameB
  # print("Merging names {} and {} into {}_or_{}".format(nameA, nameB, nameA, nameB))
  return nameA + "_or_" + nameB


def fixNameForIda(suggestedName):
    # Look and see if the arg list is attached, if so, throw away
    if ( suggestedName.find('(') != -1 ):
        # print("Removing arg list from function name {}".format(suggestedName))
        suggestedName = suggestedName[:suggestedName.index('(')]

    # Any spaces?  If so, split on spaces and select last chunk
    if ( suggestedName.find(' ') != -1 ):
        chunks = suggestedName.split(' ')
        suggestedName = chunks[-1]

    if (suggestedName.startswith("~")):
        suggestedName = suggestedName + "_destructor"
        suggestedName = suggestedName[1:]

    # Add anything else you end up spotting in the wild that doesn't work
    invalidCharsReplaceUnderscore = [ ",", " ", "?", "." ]
    invalidCharsReplaceEmpty      = [ "(", ")" ]

    for singleInvalidChar in invalidCharsReplaceUnderscore:
        suggestedName = suggestedName.replace(singleInvalidChar, "_")

    for singleInvalidChar in invalidCharsReplaceEmpty:
        suggestedName = suggestedName.replace(singleInvalidChar, "")

    return suggestedName


def deconflictName(suggestedName, discoveredNames):
    nameAttemptNum = 0
    while True:
        if (nameAttemptNum == 0):
            curAttempt = fixNameForIda(suggestedName)
        else:
            curAttempt = fixNameForIda(suggestedName) + str(nameAttemptNum)

        #print("Attempting function name for deconflict: ", curAttempt)

        if (curAttempt not in discoveredNames):
            if (nameAttemptNum != 0):
                print "Function name {} had a conflict, non-conflicting name is {}".format(suggestedName, curAttempt)

            return curAttempt

        nameAttemptNum += 1

# Much of the body of this function was also taken from func_renamer.py main script body
def scanIdaDatabaseAndRename(symbolNames, kernelSymbolsOffset, addressModVal):

    discoveredNames = []
    funcStartAddr = 0

    dlg = QtWidgets.QDialog()
    ui = RenameSelectionGui()
    ui.setupUi(dlg)

    # List of function info lists(start, end, name)
    funcInfoBefore = []
    funcList = []

    while True:
        funcStartAddr = NextFunction(funcStartAddr)
        funcName = GetFunctionName(funcStartAddr)
        if (funcName == ""):
            break
        
        funcList.append(funcName)

        functionInfoEntry = []
        functionInfoEntry.append(funcStartAddr)
        functionInfoEntry.append(funcName)
        funcInfoBefore.append(functionInfoEntry)

    print("We have found {} functions in the kernel".format(len(funcInfoBefore)))

    for fInfo in funcInfoBefore:
        funcStartAddr = fInfo[0]
        funcName      = fInfo[1]

        #print ("Func start: ", hex(funcStartAddr), " and ends ", hex(func_end_addr), "name=", funcName)

        if (funcName.startswith("sub_")):
            kernelSymAddr = funcStartAddr + kernelSymbolsOffset
            kernelSymAddr = kernelSymAddr % addressModVal
            if kernelSymAddr in symbolNames:

                suggestedName = symbolNames[kernelSymAddr]
                if (suggestedName != ""):
                    # A name has been suggest, but what if we have already discovered this name before,
                    # and more than one function have the same name.  We should just add a number on
                    # the end and find a name not taken yet
                    nonConflictName = deconflictName(suggestedName, funcList)
                    discoveredNames.append(nonConflictName)
                    ui.addItem(funcStartAddr, funcName, nonConflictName)
                    funcList.append(nonConflictName)
            else:
                print("We don't have a function in our table for: {}".format(funcName))
        
        else:
            # This function already has a name that is not sub_
            print("Ignoring function at address {}, it already has a name".format(hex(funcStartAddr)))
    
    print("Found names in the symbol file for {} functions".format(len(discoveredNames)))

    ui.adjustColumnWidths()
    dlg.exec_()


def main():

  print("Starting the Linux Kernel Symbol Loader script")

  info = idaapi.get_inf_structure()
  addressModVal = 0
  if info.is_64bit():
    print("Detected 64-bit")
    addressModVal = 0x10000000000000000
  else:
    print("Detected 32-bit")
    addressModVal = 0x100000000

  mapFiles = promptUserFile()

  print("Map Files: {}".format(str(mapFiles)))

  if (len(mapFiles) < 1):
    return

  symMap = readSymbolMapFile(mapFiles[0])

  offsetDlg = QtWidgets.QInputDialog()
  offsetDlg.setInputMode(QtWidgets.QInputDialog.TextInput)
  offsetDlg.setLabelText("What value should I add to the address in IDA to get the addresses in Symbols file\nEnter a signed integer (1234), or a positive hex value (0x1234), or a negative hex value (-0x1234)")
  offsetDlg.setTextValue("0x0")
  offsetDlg.exec_()

  offsetValue = 0
  offsetText = offsetDlg.textValue().strip()
  if ("0x" in offsetText):
    # The value is in hex
    if (offsetText[0] == '-'):
      # The value is negative
      offsetValue = -1 * int(offsetText[1:].replace("0x",""), 16)
    else:
      # Positive hex value
      offsetValue = int(offsetText.replace("0x", ""), 16)
  else:
    offsetValue = int(offsetText)

  print("We found {} symbols to use for function naming in your symbol file".format(len(symMap)))

  scanIdaDatabaseAndRename(symMap, offsetValue, addressModVal)

  print("Linux Kernel Symbol Loader script complete")

if __name__ == "__main__":
  # Uncomment to test without running in IDA
  # app = QtWidgets.QApplication(sys.argv)

  main()

  

