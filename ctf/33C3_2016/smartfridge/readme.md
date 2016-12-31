# smartfridge1

Tool to retrieve flag for the smartfridge1 reversing challenge for 33C3 CTF 2016

I unfortunately didn't complete the CTF within the timelimit of the challenge.

## Description of challenge

Description: We've developed a new smart refrigerator with networking functionality. We have
adopted the proven Bluetooth LE 4.0 crypto protocol to secure your food from your flatmates.
There are two lockable shelves. Shelf number 1 belongs to you. Find the fridge at (ip removed).
The pincode for your shelf is 768305. In it you will find the first flag.

* Note: this challenge is rate limited

Also was given a binary of the application that we could run ourselves and analyze

## Server Info

The port number of the server wasn't explicitly given, but it was available by nmap-ing the real
game server, executing netstat before and after running their instance, or static analysis.

I'm hesitant to trust binaries from unknown sources, so I ran my server in a VM, and did most of
my testing against it

## To compile and execute tool

Compilation:

>  g++ main.cpp -lcrypto -o fc

Execution:

>  ./fc 127.0.0.1 12345 1 12345

## Sample execution / output

Flags are stored on a remote server.  Below is the output of me running the application and getting the flag:

```
mwales@Galaga:~/checkouts/security/ctf/33C3_2016/smartfridge1$ ./fc 123.123.123.123 12345 1 768305
Shelf Num = 1
Pin Code = 768305
Pin Block:
31 b9 0b 00 00 00 00 00  00 00 00 00 00 00 00 00

MRand:
00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff

MConfirm:
3e b6 30 5f 6a 94 37 5c  63 e0 f3 fb c8 d0 e5 4e
About to send the MConfirmMsg
15 00 00 00 01 3e b6 30  5f 6a 94 37 5c 63 e0 f3
fb c8 d0 e5 4e 
SConfigSize = 20
b6 32 fc 16 23 a4 59 8b  28 18 b3 35 4a 70 98 99
About to send the MRand
14 00 00 00 00 11 22 33  44 55 66 77 88 99 aa bb
cc dd ee ff 
SRand Received.  Msg Size = 20
8f 4b 0c ae f8 43 49 d3  ef ae 3f 40 b1 f0 d8 d0

Derived AES session key:
a9 b6 59 b8 f9 b5 e7 02  89 2b 35 93 d8 4a e5 f2
Enter a command (or exit to close client)
Valid commands from reversing:
  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)
  LIST                          (lists contents of shelf, use OPEN first)
  SHOW ItemNumber               (displays the item description)
  PUT ItemNumber Name Desc      (adds an item to the shelf)
  TAKE ItemNumber               (shows item, then removes from shelf)
  CLOSE
OPEN 1

Encrypting message of length 7, blocks required = 1, padding byte = 9
No response expected for command: OPEN 1
Enter a command (or exit to close client)
Valid commands from reversing:
  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)
  LIST                          (lists contents of shelf, use OPEN first)
  SHOW ItemNumber               (displays the item description)
  PUT ItemNumber Name Desc      (adds an item to the shelf)
  TAKE ItemNumber               (shows item, then removes from shelf)
  CLOSE
LIST

Encrypting message of length 5, blocks required = 1, padding byte = 11
Response rx length = 52
5d cf 1e f3 cf 2b 48 3b  bb 84 aa 19 aa 07 20 10
6b 68 4b 3f 1f f3 08 6e  0c 75 1b 31 36 3f af 93
9e 6d 9b 79 31 c9 3f a1  01 47 c6 70 be 5f 45 5c

Decrypting Ciphertext:
5d cf 1e f3 cf 2b 48 3b  bb 84 aa 19 aa 07 20 10
6b 68 4b 3f 1f f3 08 6e  0c 75 1b 31 36 3f af 93
9e 6d 9b 79 31 c9 3f a1  01 47 c6 70 be 5f 45 5c
Plaintext:
30 2e 20 74 6f 61 73 74  0a 31 2e 20 62 72 65 61
64 0a 32 2e 20 77 61 74  65 72 0a 33 2e 20 54 68
75 6e 66 69 73 63 68 0a  34 2e 20 0a 04 04 04 04
Plaintext in ASCII:
0. toast
1. bread
2. water
3. Thunfisch
4. 

Enter a command (or exit to close client)
Valid commands from reversing:
  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)
  LIST                          (lists contents of shelf, use OPEN first)
  SHOW ItemNumber               (displays the item description)
  PUT ItemNumber Name Desc      (adds an item to the shelf)
  TAKE ItemNumber               (shows item, then removes from shelf)
  CLOSE
SHOW 0
Encrypting message of length 7, blocks required = 1, padding byte = 9
Response rx length = 52
d4 fd b9 82 35 b2 6f d4  c0 84 3b b5 f2 e9 47 d8
d7 58 fd b1 b3 c5 d1 0b  5b 04 4c 21 83 0b a2 44
73 d7 a0 48 d9 4c 18 bd  95 5b 07 73 35 d7 21 a2

Decrypting Ciphertext:
d4 fd b9 82 35 b2 6f d4  c0 84 3b b5 f2 e9 47 d8
d7 58 fd b1 b3 c5 d1 0b  5b 04 4c 21 83 0b a2 44
73 d7 a0 48 d9 4c 18 bd  95 5b 07 73 35 d7 21 a2
Plaintext:
74 6f 61 73 74 3a 20 33  33 43 33 5f 73 31 69 6d
70 6c 33 5f 34 73 79 6e  63 5f 73 33 72 76 65 72
0a 0f 0f 0f 0f 0f 0f 0f  0f 0f 0f 0f 0f 0f 0f 0f
Plaintext in ASCII:
toast: 33C3_s1impl3_4sync_s3rver

Enter a command (or exit to close client)
Valid commands from reversing:
  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)
  LIST                          (lists contents of shelf, use OPEN first)
  SHOW ItemNumber               (displays the item description)
  PUT ItemNumber Name Desc      (adds an item to the shelf)
  TAKE ItemNumber               (shows item, then removes from shelf)
  CLOSE
exit

Encrypting message of length 5, blocks required = 1, padding byte = 11
Response rx length = 48
d4 fd b9 82 35 b2 6f d4  c0 84 3b b5 f2 e9 47 d8
d7 58 fd b1 b3 c5 d1 0b  5b 04 4c 21 83 0b a2 44
73 d7 a0 48 d9 4c 18 bd  95 5b 07 73 
Incoming cipher text length of 44 is invalid block size
```

## IDA notes

The core functions were in a function called handle, which Hex-Rays decompiled into a giant mess.
But switching back and forth between assembly view, graph view, debugger, and decompiled version,
was able to understand most of it.

And one of the key structures, was a structure that was used for each client that connected.


![IDA Structure](ClientDataIdaStruct.png)

# smartfridge2

## Description

Given a PCAP of a client connecting, could we take the flag from a shelf that we don't have the
pin code for?

## Analysis

The protocol calls for MRand, SRand, MConfirm, and SConfirm to be sent in the clear.  Once the
connection is in paired mode, all traffic is encrypted.

MConfirm is derived from MRand and PinCode.  Since we have MRand from the PCAP as well, we can
use this information to create a brute force cracker.  The pin code was very short, so the crack
completes in less than 1 second.

```
time ./crack
Found the pin: 482633

real    0m0.171s
user    0m0.168s
sys     0m0.000s
```

Then used the client from smartfridge1 to connect to the fridge are extract the flag.

```
mwales@Galaga:~/checkouts/security/ctf/33C3_2016/smartfridge1$ ./fc 123.123.123.123 12345 2 482633
Shelf Num = 2
Pin Code = 482633
Pin Block:
49 5d 07 00 00 00 00 00  00 00 00 00 00 00 00 00

MRand:
00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff

MConfirm:
bc f9 7a e8 4e c0 c2 27  7f ed b7 88 e5 82 86 34
About to send the MConfirmMsg
15 00 00 00 02 bc f9 7a  e8 4e c0 c2 27 7f ed b7
88 e5 82 86 34
SConfigSize = 20
8b 88 e1 2f f9 6e c4 24  bd 2d 18 d6 9d b6 b6 11
About to send the MRand
14 00 00 00 00 11 22 33  44 55 66 77 88 99 aa bb
cc dd ee ff
SRand Received.  Msg Size = 20
97 41 62 db 9e b2 44 1b  b6 20 a3 82 ec 07 56 e5

Derived AES session key:
50 33 df fd 6d 94 73 0f  b6 c6 72 a6 b4 41 ec f3
Enter a command (or exit to close client)
Valid commands from reversing:
  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)
  LIST                          (lists contents of shelf, use OPEN first)
  SHOW ItemNumber               (displays the item description)
  PUT ItemNumber Name Desc      (adds an item to the shelf)
  TAKE ItemNumber               (shows item, then removes from shelf)
  CLOSE
OPEN 2

Encrypting message of length 7, blocks required = 1, padding byte = 9
No response expected for command: OPEN 2
Enter a command (or exit to close client)
Valid commands from reversing:
  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)
  LIST                          (lists contents of shelf, use OPEN first)
  SHOW ItemNumber               (displays the item description)
  PUT ItemNumber Name Desc      (adds an item to the shelf)
  TAKE ItemNumber               (shows item, then removes from shelf)
  CLOSE
LIST

Encrypting message of length 5, blocks required = 1, padding byte = 11
Response rx length = 36
6a 65 84 71 15 9e a0 a9  13 bb fe 6d bb ac 70 26
fa 7c df a7 3a 81 a7 ff  56 4f aa b6 b7 f0 50 51

Decrypting Ciphertext:
6a 65 84 71 15 9e a0 a9  13 bb fe 6d bb ac 70 26
fa 7c df a7 3a 81 a7 ff  56 4f aa b6 b7 f0 50 51
Plaintext:
30 2e 20 79 6f 67 68 75  72 74 0a 31 2e 20 0a 32
2e 20 0a 33 2e 20 0a 34  2e 20 0a 05 05 05 05 05
Plaintext in ASCII:
0. yoghurt
1.
2.
3.
4.

Enter a command (or exit to close client)
Valid commands from reversing:
  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)
  LIST                          (lists contents of shelf, use OPEN first)
  SHOW ItemNumber               (displays the item description)
  PUT ItemNumber Name Desc      (adds an item to the shelf)
  TAKE ItemNumber               (shows item, then removes from shelf)
  CLOSE
SHOW 0

Encrypting message of length 7, blocks required = 1, padding byte = 9
Response rx length = 52
cf 05 7d b1 e9 4b 52 e9  cc 2c fe dd 93 93 07 90
09 04 6b 70 18 0f 52 3e  d8 d0 2a 66 63 e7 e3 48
e9 81 75 c6 df e3 04 55  95 30 dc 17 f7 b3 0e a0

Decrypting Ciphertext:
cf 05 7d b1 e9 4b 52 e9  cc 2c fe dd 93 93 07 90
09 04 6b 70 18 0f 52 3e  d8 d0 2a 66 63 e7 e3 48
e9 81 75 c6 df e3 04 55  95 30 dc 17 f7 b3 0e a0
Plaintext:
79 6f 67 68 75 72 74 3a  20 33 33 43 33 5f 73 68
30 72 74 5f 70 34 73 73  63 30 64 65 5f 31 73 5f
73 68 4f 72 74 0a 0a 0a  0a 0a 0a 0a 0a 0a 0a 0a
Plaintext in ASCII:
yoghurt: 33C3_sh0rt_p4ssc0de_1s_shOrt
```
