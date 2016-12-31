Flags are stored on a remote server.  Below is the output of me running the application and getting the flag:

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

I unfortunately didn't complete the CTF within the timelimit of the challenge.  
