# Reverse Box

This challenge gave you an application, and some output from the application.  To get the flag,
you had to determine what input generated the output given.

So running the application a few times reveals alot...

   $ ./reverse_box flaggoeshere
   7013acc6c6eb0ecc060e030e
   $ ./reverse_box flaggoeshere
   791aa5cfcfe207c50f070a07
   $ ./reverse_box flaggoeshere
   ddbe016b6b46a361aba3aea3

The output length stays the same for each run (2x as long as the input).  It should also be obvious
that the output keeps changing!  A bit unusual...  Looking at the code via IDA or debugger reveals
this little tidbit...  

```
// Function prologue stuff

.text:0804858D                   createCipher    proc near               ; CODE XREF: main+52p
.text:0804858D
.text:0804858D 55                                push    ebp        
.text:0804858E 89 E5                             mov     ebp, esp
.text:08048590 83 EC 28                          sub     esp, 28h

// eax = time(NULL);
.text:08048593 C7 04 24 00 00 00+                mov     dword ptr [esp], 0 ; timer
.text:0804859A E8 61 FE FF FF                    call    _time
.text:0804859F 89 04 24                          mov     [esp], eax      ; seed

// srand(eax)
// Random number now seeded with time since epoch...
.text:080485A2 E8 99 FE FF FF                    call    _srand
.text:080485A7


.text:080485A7                   loc_80485A7:                            ; CODE XREF: createCipher+2Bj

// eax = rand()
// Get a random number in eax
.text:080485A7 E8 D4 FE FF FF                    call    _rand

// Store random value & 0xFF in a variable in memory
// Basically generating a random number 0-255
.text:080485AC 25 FF 00 00 00                    and     eax, 0FFh
.text:080485B1 89 45 F4                          mov     [ebp+randomVal1To255], eax
.text:080485B4 83 7D F4 00                       cmp     [ebp+randomVal1To255], 0

// Pick a new random number if you happen to end up with zero
// Basically generating a random number 1-255
.text:080485B8 74 ED                             jz      short loc_80485A7

// Now do stuff with that random number...
.text:080485BA 8B 45 F4                          mov     eax, [ebp+randomVal1To255]
.text:080485BD 89 C2                             mov     edx, eax
.text:080485BF 8B 45 08                          mov     eax, [ebp+offsetTableStartAddr]
```

At first I thought this was just generating a single random offset to apply to all the characters
in the argument to reverse_box.  So I tried unsuccessfully to solve it that way.  I later realized
that there is a different offset in the ASCII table for each letter.

Later it occured to me that a character in the input would generate the same output no matter where
we were in the input stream.  The code was implementing a subsitition (Caesar) style cipher.

## Solution

The random number is only queried once, and the output is masked, so there are only 254 random
possible ciphers.  I have no idea what the cipher looks like, but if I had all of them, I could
then test each of them to see which one looks like a valid CTF flag.

Something like...

```
$ ./reverse_box abcdefghijklmnopqrstuvwxyz
a0e5b40c027cca0ab64d301f73d0e71eec0fc0ddd277baf3f995
$ ./reverse_box abcdefghijklmnopqrstuvwxyz
2663328a84fa4c8c30cbb699f55661986a89465b54f13c757f13
```

I could just run this over and over until all cipher possibilities.  But since the random number
generated is time seeded, I will need to wait 1+ second for each iteration (254 seconds at least).
And some may repeat, this could take 5+ minutes...

What would be way faster, is to remove the randomness from the application via a patch, and then
run it in a repeatable way.  Basically, just force eax to be 1, or 2, or 3, etc when we run the
program.

So I create the ELF patching program int utils folder.  (Fyi, this way not way faster, learned
a lot how to take apart an ELF though).

My new utility can be given a range of virtual addresses, and opcodes to place in the binary
at the location.  Any extra room will be converted to NOPs.

Using this cool online assembler (https://defuse.ca/online-x86-assembler.htm), I determine:

   b8 55 00 00 00          mov    eax,0x55

And I can replace 0x55 with any hex value I like.  I will implement this in place of the code
that keeps looping until a random non-zero number is generated.

   ./patch32 reverse_box.hacked 0x80485ac 0xe b855000000

This didn't quite work, I forgot about the instructions to store this as a variable in memory (and
not just leave it in the register).  I just copied the existing opcodes from the existing binary.

   89 45 F4                          mov     [ebp+randomVal1To255], eax

So my patching application would be configured like:

./patch32 reverse_box.hacked 0x80485ac 0xe b8550000008945f4


Output from the patching process:

```
$ ./patch32
Usage: ./patch32 elf_file VMA_Start NumBytes PatchBytesHex
 All bytes after the patch will be NOPed until NumBytes reached
$
$ ./patch32 reverse_box.hacked 0x80485ac 0xe b8550000008945f4
ELF Type = Executable File
Machine Type = Intel 386
Sec#       Section Name    VirtAddr        Size  FileOffset
 0                       0x00000000  0x00000000  0x00000000
 1              .interp  0x08048154  0x00000013  0x00000154
 2        .note.ABI-tag  0x08048168  0x00000020  0x00000168
 3   .note.gnu.build-id  0x08048188  0x00000024  0x00000188
 4            .gnu.hash  0x080481ac  0x00000020  0x000001ac
 5              .dynsym  0x080481cc  0x000000c0  0x000001cc
 6              .dynstr  0x0804828c  0x00000086  0x0000028c
 7         .gnu.version  0x08048312  0x00000018  0x00000312
 8       .gnu.version_r  0x0804832c  0x00000030  0x0000032c
 9             .rel.dyn  0x0804835c  0x00000008  0x0000035c
10             .rel.plt  0x08048364  0x00000050  0x00000364
11                .init  0x080483b4  0x00000023  0x000003b4
12                       0x080483e0  0x000000b0  0x000003e0
13                .text  0x08048490  0x00000342  0x00000490
14                .fini  0x080487d4  0x00000014  0x000007d4
15              .rodata  0x080487e8  0x0000001d  0x000007e8
16        .eh_frame_hdr  0x08048808  0x00000034  0x00000808
17            .eh_frame  0x0804883c  0x000000d4  0x0000083c
18          .init_array  0x08049f08  0x00000004  0x00000f08
19          .fini_array  0x08049f0c  0x00000004  0x00000f0c
20                 .jcr  0x08049f10  0x00000004  0x00000f10
21             .dynamic  0x08049f14  0x000000e8  0x00000f14
22                 .got  0x08049ffc  0x00000004  0x00000ffc
23             .got.plt  0x0804a000  0x00000034  0x00001000
24                .data  0x0804a034  0x00000008  0x00001034
25                 .bss  0x0804a03c  0x00000004  0x0000103c
26             .comment  0x00000000  0x0000004f  0x0000103c
27            .shstrtab  0x00000000  0x000000f6  0x0000108b
Virtual Address 0x080485ac is at file offset 0x000005ac
Patching!
Patch Success
```

Which has turned the code into...

```
(gdb) set disassembly-flavor intel
(gdb) x/20i 0x0804858d
   0x804858d:   push   ebp
   0x804858e:   mov    ebp,esp
   0x8048590:   sub    esp,0x28
   0x8048593:   mov    DWORD PTR [esp],0x0
   0x804859a:   call   0x8048400 <time@plt>
   0x804859f:   mov    DWORD PTR [esp],eax
   0x80485a2:   call   0x8048440 <srand@plt>
   0x80485a7:   call   0x8048480 <rand@plt>
   0x80485ac:   mov    eax,0x55               <---- Beginning of my patch
   0x80485b1:   mov    DWORD PTR [ebp-0xc],eax
   0x80485b4:   nop
   0x80485b5:   nop
   0x80485b6:   nop
   0x80485b7:   nop
   0x80485b8:   nop
   0x80485b9:   nop                           <---- End of the patch
   0x80485ba:   mov    eax,DWORD PTR [ebp-0xc]
   0x80485bd:   mov    edx,eax
   0x80485bf:   mov    eax,DWORD PTR [ebp+0x8]
   0x80485c2:   mov    BYTE PTR [eax],dl
```

I then created a python script to run the patcher for all possible values 0x01-0xff.  The program
is then called with as much of the ASCII table as possible for shell input.  Then for each cipher
generated, it would then try to determine what the input would be to generate the challenge output.

   ./generate_ciphers.py `cat reverse_box_flag_output.txt`

This will generate a block of input like the following for each trial:

```
Cipher Index 85
Patching: ./patch32 reverse_box.hacked 0x80485ac 0xe b8550000008945f4
32f115f52ea033ac31b51a2c2d586c96640de0851fd519b265e736db16ca876d5cfdd99ccd757b05b373cf3449660aa99e679576b9a4ab0ec38a8017c9eef9

Plaintext:             0 1 2 3 4 5 6 7 8 A B C D E F G H I J K L M N O P Q R S T U V W X Y a b c d e f g h i j k l m n o p q r s t u v w x y { } - _ 
Key Ciphercode         32f115f52ea033ac31b51a2c2d586c96640de0851fd519b265e736db16ca876d5cfdd99ccd757b05b373cf3449660aa99e679576b9a4ab0ec38a8017c9eef9

Cipher Text to decode: 95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a
Input to keygen:       q- q   k E   k        QrA -  Q A      Gr   W    
```

Running the script again, just grepping for the keygen line that will contain the solution:

```
$ ./generate_ciphers.py `cat reverse_box_flag_output.txt` | grep keygen
<lots of output>
Input to keygen:              c  u ucu         8   u  8                
Input to keygen:             t    3   3R Y 3  10Y 3  Y0   R 3 1 Yt  REc
Input to keygen:              iL n nin         6   n  6            L   
Input to keygen:         4  2   a         4 pl j    l jC     {         
Input to keygen:       2  2   }N    }  8B   lp      p  DB48  T 4   N8 U
Input to keygen:       TWCTF{5UBS717U710N_C1PH3R_W17H_R4ND0M123D_5-B0X}
Input to keygen:       {FD{WT          6  D HP   F  P    C6    C    6  
Input to keygen:            N   M       {               {  S      J    
Input to keygen:       N  N    2        T               T    B     2   
Input to keygen:       B  B  7 T 5Y5 5Y 23 Y  _ 3 Y5 3  2  aYN_ 37 T   
Input to keygen:            B  {                                   {   
Input to keygen:        p  l                     p           L        w

So flag is...

TWCTF{5UBS717U710N_C1PH3R_W17H_R4ND0M123D_5-B0X}





