
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

class Ui_Dialog(object):
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
        self.buttonBox.accepted.connect(okClicked)
        self.buttonBox.rejected.connect(Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

        self.pushButton.clicked.connect(invertAllClicked)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Rename Confirmation"))
        self.pushButton.setText(_translate("Dialog", "Invert All"))

    def addItem(self, address, curName, newName):
        rowInfo = []

        # store internally important stuff to prcess later
        cb = QtWidgets.QCheckBox()
        rowInfo.append(cb)
        rowInfo.append(address)
        rowInfo.append(newName)

        curRow = len(self.renameData)

        if (self.tableWidget.rowCount() == curRow):
            # Add a new row!
            self.tableWidget.setRowCount(curRow + 1)

        print("Adding a row to the table at curRow = ", curRow)
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
        print("Rename functions!")
        for rowData in self.renameData:
            if (rowData[0].isChecked()):
                print("Renaming ", rowData[1], " to ", rowData[2])
                MakeName(rowData[1], rowData[2])




def invertAllClicked():
    print("Invert all clicked")
    ui.invertAll()

def okClicked():
    print("OK Clicekd")
    ui.renameFunctions()

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

def deconflictName(suggestedName, discoveredNames):
    nameAttemptNum = 0
    while True:
        if (nameAttemptNum == 0):
            curAttempt = suggestedName
        else:
            curAttempt = suggestedName + str(nameAttemptNum)

        print("Attempting function name for deconflict: ", curAttempt)

        if (curAttempt not in discoveredNames):
            return curAttempt

        nameAttemptNum += 1





traceFunc = ChooseFunction("Function that is used for trace statements?")
searchString = GetFunctionName(traceFunc)
print("User picked: ", searchString)

paramIndex = AskLong(1, "Which argument of the function is the function name (0, 1, 2, ...)?")
if (paramIndex is None) or (paramIndex == 0xffffffff):
    print ("Invalid choice", paramIndex)
else:


    discoveredNames = []
    funcStartAddr = 0

    dlg = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(dlg)

    # List of function info lists(start, end, name)
    funcInfoBefore = []
    funcList = []

    while (funcStartAddr != 0xffffffff):

        funcStartAddr = NextFunction(funcStartAddr)
        funcEndAddr = FindFuncEnd(funcStartAddr)
        funcName = GetFunctionName(funcStartAddr)
        funcList.append(funcName)

        functionInfoEntry = []
        functionInfoEntry.append(funcStartAddr)
        functionInfoEntry.append(funcEndAddr)
        functionInfoEntry.append(funcName)
        funcInfoBefore.append(functionInfoEntry)

    for fInfo in funcInfoBefore:
        funcStartAddr = fInfo[0]
        funcEndAddr   = fInfo[1]
        funcName      = fInfo[2]

        #print ("Func start: ", hex(funcStartAddr), " and ends ", hex(func_end_addr), "name=", funcName)

        if (funcName.startswith("sub_")):
            suggestedName = analyzeSingleFunction(funcStartAddr, funcEndAddr, searchString, paramIndex)

            if (suggestedName != ""):
                # A name has been suggest, but what if we have already discovered this name before, and more than one function
                # have the same name.  We should just add a number on the end and find a name not taken yet
                nonConflictName = deconflictName(suggestedName, funcList)
                discoveredNames.append(nonConflictName)
                ui.addItem(funcStartAddr, funcName, nonConflictName)
                funcList.append(nonConflictName)



    ui.adjustColumnWidths()
    dlg.show()

print("Done.")
