### Linux syscall tables

HaoE says they are normally (used to be) in /usr/include/asm-i386/unistd.h

On Ubuntu 14.04 systems, they are in:

/usr/include/x86_64-linux-gnu/asm/unistd_32.h
/usr/include/x86_64-linux-gnu/asm/unistd_64.h

### To turn ASLR on and off

'''
/proc/sys/kernel/randomize_va_space
'''

0 = no randomization
1 = conservative randomization.  shared libraries, stack, mmap(), and heap are randomized
2 = full randomization

### How to control stack cookies

Compile with -fno-stack-protector

### How to control DEP (data execution prevention)

Compile with -z execstack

### Intel vs ATT syntax

For gdb, set syntax:
'''
set disassembly-flavor intel
'''

ATT:

mov %eax, %edx
instruction source, dest

Intel:

mov edx, eax
instruction dest, source

Compare (Intel) goes left to right

* BYTE = 8 bits = char
* WORD = 16 bits = short
* DWORD = 32-bits = int
* QWORD = 64-bit = long long

* .text = program instructions
* .data = initialized global variables
* .bss = uninitialized global variables

eax usually holds return value on x86

ebp (base pointer) - offset = local variables
ebp (base pointer) + offset = function arguement passed on stack

if conditions are actually the opposite for assembly.  if (x>y) becomes cmp x, y, followed by jle 
(less than or equal).  Basically, if the condition fails, we are going to jump over the code in the
if block.

## Calling conventions

Recent GCC / Linux will force stack frames to be on 16-byte boundaries

### cdecl

For C programming language:

* Args are pused on the stack (right to left)
* Integers and pointers are returned via EAX
* Floats are returned via STO
* After the call returns, the caller removes the args from the stack (add sp, 4), and pops ebp

### fastcall

For C programming language:

* First arg passed via ECX, second arg passed via EDX, and rest of the args are pushed on stack 
  (right to left)

### Unix/Linux/Mac AMD64

* First 6 integer args are passed via registers:  rdi, rsi, rdx, rcx/r10, r8, r9.
* Floats are passed via xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
* Additional args are passed on stack
* Return value is stored in RAX and RDX



## GDB Cheatsheet

set disassembly-flavor intel

### Examine command

x/nfu
* n = number of units
* f = format
* u = unit

Formats:
* x/o = examine in octal
* x/x = examine in hexadecimal
* x/u = examine in unsigned base-10 decimal
* x/t = examine in binary
* x/s = examine as string
* x/i = examine instructions

Units:
* x with b = examine bytes
* x with h = half-words (16-bit)
* x with w = word (32-bit)
* x with g = giant (64-bit)

#### Examples

* x/8xb $eip = examine 8 bytes at EIP address (in hex)
* x/4xw addr = examine 4 32-bit words at address (in hex)

### Controlling execution

* p / print = print out a variable (usually will smartly output structures and what not)
* s / step = steps 1 line of code, including diving into functions
* n / next = steps 1 instruction, not diving into functions
* si / stepi = steps 1 assembly instruction, including diving into functions
* ni / nexti = steps 1 assembly instruction, not diving into functions
* finish = continue execution until we leave this function
* continue = detach debugger and let the code run

### Stack stuff

* bt = backtrace
* up = move debugger up 1 frame
* down = move debugger down 1 frame
* frame x = move to frame x
* info args = list function arg values
* info locals = list local variables and values

### Setting memory location

set *((int *) 0xdeadbeef) = 0xf00dd00d

### Scripting a break point

break someFunc
commands
  i r
end

The commands command in GDB also has an argument.  If no arg passed, it assumes
you are trying to script the last breakpoint added.  Otherwise, pass the
breakpoint number of the breakpoint you are trying to script

# GDB Custom Commands / Functions

GDB functions / custom commands have an unlimited number of args

Number of args passed

  $argc

Args themselves:

  $arg0
  $arg1
  ... and so on

GDB allows local internal variables (convenience variables)

  set $myVar = 0x1234

# GDB function to print out wstrings

define printWString

  if $argc != 1

    printf "Usage incorrect, provide the starting address of the wstring\n"
  else 

    set $addressOfWString = $arg0
    set $index = 0
    set $currentChar = *($addressOfWString + $index)
    while $currentChar != 0x0
      printf "%c", $currentChar
      set $index = $index + 2
      set $currentChar = *($addressOfWString + $index)
    end
  
    printf "\n"
  end
end
document printWString
Prints a wide string (16-bit characters) starting at the addressed passed to it until it reaches 0x0000
end

define printQString
  if $argc != 1
    printf "Incorrect usage, provide the address of the QString\n"
  else
    set $addressOfString = $arg0 + 0x18

    printWString $addressOfString
  end
end
document printQString
Prints a QString data string using printWString
end

# Installing IDA 6.95 on Linux

If you don't do the following steps on Ubuntu Linux derivatives around trusty (14.04), you will get 
all of the Ida Pro menu options all squished together, and the drop down menus will be blank.

As documented in the blog post: http://www.hexblog.com/?p=1048

<code>
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install libc6-i686:i386 libexpat1:i386 libffi6:i386 libfontconfig1:i386 libfreetype6:i386 libgcc1:i386 libglib2.0-0:i386 libice6:i386 libpcre3:i386 libpng12-0:i386 libsm6:i386 libstdc++6:i386 libuuid1:i386 libx11-6:i386 libxau6:i386 libxcb1:i386 libxdmcp6:i386 libxext6:i386 libxrender1:i386 zlib1g:i386 libx11-xcb1:i386 libdbus-1-3:i386 libxi6:i386 libsm6:i386 libcurl3:i386 

# In addition, it is also necessary to install the
# following packages, for IDA to present a usable
# & well-integrated GUI on many Debian & Ubuntu
# desktops. If the set of dependencies above are
# not enough to obtain a slick UI, please 
# install the following:

sudo apt-get install libgtk2.0-0:i386 gtk2-engines-murrine:i386 gtk2-engines-pixbuf:i386 libpango1.0-0:i386
</code>

# Core Files

```
ulimit -c unlimited
```

Is usually all that is needed, but occasionally this will help if the core isn't going where it should...

```
sudo sysctl -w kernel.core_pattern=core
```

And if you just want core dump of running application, check out gcore

