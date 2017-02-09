# Crypto challenge 1:

Big blob of text that was "ZERO ONE ZERO ..."

Wrote a [program (decoder.cpp)](decoder.cpp) to decode it into ASCII...

```
Li0gLi0uLiAuIC0uLi0gLS4tLiAtIC4uLS4gLSAuLi4uIC4tLS0tIC4uLi4uIC0tLSAuLS0tLSAuLi4gLS0tIC4uLi4uIC4uLSAuLS0uIC4uLi0tIC4tLiAtLS0gLi4uLi4gLiAtLi0uIC4tLiAuLi4tLSAtIC0tLSAtIC0uLi0gLQ==
```

So, base64 decoded that...

```
.- .-.. . -..- -.-. - ..-. - .... .---- ..... --- .---- ... --- ..... ..- .--. ...-- .-. --- ..... . -.-. .-. ...-- - --- - -..- -
```

wtf, lol.  Found an online morse code translator...

```
ALEXCTFTH15O1SO5UP3RO5ECR3TOTXT
```
Modified formatting to be more flag like...

```
FLAG ALEXCTF{TH15_1S_5UP3R_5ECR3T_TXT}
```

# Crypto challenge 2:

I didn't finish this challenge within the time frame of the CTF, but I did finish it the next day
or two.  Dan Boneh's (Stanford) Coursera Cryptography I course actually has a homework problem
that is just like this.  I couldn't actually find my homework source code though, so I had to 
reinvent the wheel.

I went around and around on this, but in the end I came up with a way better solution than I had
when I did the homework for the Coursera class.

You can google search for to see how the attack on multiple uses of a one time pad work when
encrypting ASCII text data.  This [stack exchange answer](http://crypto.stackexchange.com/a/6095)
by Ilmari Karonen summed it up quite well I thought.

For my [application (otp.cpp)](otp.cpp), you provide a [key](otp_key.txt) as the first line 
of input to the application, and then the [ciphertext message data (otp_msg.txt)](otp_msg.txt)
to decrypt as the rest of the input.  It will decrypt the data using the provided key and
output the plaintext.  It will also try to derive the key itself, decrypt the data, and then
display the derived plaintext.

Sample run:

```
cat otp_key.txt otp_msg.txt | ./otp                                                                                                                                                    
Ciphertext = 0529242a631234122d2b36697f13272c207f2021283a6b0c7908
Ciphertext = 2f28202a302029142c653f3c7f2a2636273e3f2d653e25217908
Ciphertext = 322921780c3a235b3c2c3f207f372e21733a3a2b37263b313012
Ciphertext = 2f6c363b2b312b1e64651b6537222e37377f2020242b6b2c2d5d
Ciphertext = 283f652c2b31661426292b653a292c372a2f20212a316b283c09
Ciphertext = 29232178373c270f682c216532263b2d3632353c2c3c2a293504
Ciphertext = 613c37373531285b3c2a72273a67212a277f373a243c20203d5d
Ciphertext = 243a202a633d205b3c2d3765342236653a2c7423202f3f652a18
Ciphertext = 2239373d6f740a1e3c651f207f2c212a247f3d2e65262430791c
Ciphertext = 263e203d63232f0f20653f207f332065262c3168313722367918
Ciphertext = 2f2f372133202f142665212637222220733e383f2426386b
Verified all CTs are ASCII plaintext data
Max message len = 26
********************************************************************************
* Decrypting with key provided                                                 *
********************************************************************************
Key (len = 26) = 41 4c 45 58 43 54 46 7b 48 45 52 45 5f 47 4f 45 53 5f 54 48 45 5f 4b 45 59 7d     ALEXCTF{HERE_GOES_THE_KEY}

44 65 61 72 20 46 72 69 65 6e 64 2c 20 54 68 69 73 20 74 69 6d 65 20 49 20 75     Dear Friend, This time I u
6e 64 65 72 73 74 6f 6f 64 20 6d 79 20 6d 69 73 74 61 6b 65 20 61 6e 64 20 75     nderstood my mistake and u
73 65 64 20 4f 6e 65 20 74 69 6d 65 20 70 61 64 20 65 6e 63 72 79 70 74 69 6f     sed One time pad encryptio
6e 20 73 63 68 65 6d 65 2c 20 49 20 68 65 61 72 64 20 74 68 61 74 20 69 74 20     n scheme, I heard that it 
69 73 20 74 68 65 20 6f 6e 6c 79 20 65 6e 63 72 79 70 74 69 6f 6e 20 6d 65 74     is the only encryption met
68 6f 64 20 74 68 61 74 20 69 73 20 6d 61 74 68 65 6d 61 74 69 63 61 6c 6c 79     hod that is mathematically
20 70 72 6f 76 65 6e 20 74 6f 20 62 65 20 6e 6f 74 20 63 72 61 63 6b 65 64 20      proven to be not cracked 
65 76 65 72 20 69 66 20 74 68 65 20 6b 65 79 20 69 73 20 6b 65 70 74 20 73 65     ever if the key is kept se
63 75 72 65 2c 20 4c 65 74 20 4d 65 20 6b 6e 6f 77 20 69 66 20 79 6f 75 20 61     cure, Let Me know if you a
67 72 65 65 20 77 69 74 68 20 6d 65 20 74 6f 20 75 73 65 20 74 68 69 73 20 65     gree with me to use this e
6e 63 72 79 70 74 69 6f 6e 20 73 63 68 65 6d 65 20 61 6c 77 61 79 73 2e     ncryption scheme always.

********************************************************************************
* Decrypting with derived key                                                  *
********************************************************************************
We think for pos 0 msg 65 is a space! (10 matches)
We think for pos 1 msg 76 is a space! (10 matches)
We think for pos 2 msg 69 is a space! (10 matches)
We think for pos 3 msg 88 is a space! (18 matches)
We think for pos 4 msg 67 is a space! (21 matches)
We think for pos 5 msg 84 is a space! (10 matches)
We think for pos 6 msg 70 is a space! (10 matches)
We think for pos 7 msg 123 is a space! (24 matches)
We think for pos 8 msg 68 is a space! (9 matches)
We think for pos 9 msg 69 is a space! (30 matches)
We think for pos 10 msg 82 is a space! (10 matches)
We think for pos 11 msg 69 is a space! (24 matches)
We think for pos 12 msg 95 is a space! (30 matches)
We think for pos 13 msg 71 is a space! (10 matches)
We think for pos 14 there are no msgs with a space.  Best candidate = 0 matches
We think for pos 15 msg 69 is a space! (18 matches)
We think for pos 16 msg 83 is a space! (18 matches)
We think for pos 17 msg 95 is a space! (28 matches)
We think for pos 18 msg 84 is a space! (10 matches)
We think for pos 19 msg 72 is a space! (10 matches)
We think for pos 20 msg 69 is a space! (18 matches)
We think for pos 21 there are no msgs with a space.  Best candidate = 0 matches
We think for pos 22 msg 75 is a space! (24 matches)
We think for pos 23 msg 69 is a space! (9 matches)
We think for pos 24 msg 89 is a space! (28 matches)
We think for pos 25 msg 125 is a space! (18 matches)

Derived Key: 41 4c 45 58 43 54 46 7b 44 45 52 45 5f 47 00 45 53 5f 54 48 45 00 4b 45 59 7d 

44 65 61 72 20 46 72 69 69 6e 64 2c 20 54 27 69 73 20 74 69 6d 3a 20 49 20 75     Dear Friind, T'is tim: I u
6e 64 65 72 73 74 6f 6f 68 20 6d 79 20 6d 26 73 74 61 6b 65 20 3e 6e 64 20 75     nderstooh my m&stake >nd u
73 65 64 20 4f 6e 65 20 78 69 6d 65 20 70 2e 64 20 65 6e 63 72 26 70 74 69 6f     sed One xime p.d encr&ptio
6e 20 73 63 68 65 6d 65 20 20 49 20 68 65 2e 72 64 20 74 68 61 2b 20 69 74 20     n scheme  I he.rd tha+ it 
69 73 20 74 68 65 20 6f 62 6c 79 20 65 6e 2c 72 79 70 74 69 6f 31 20 6d 65 74     is the obly en,ryptio1 met
68 6f 64 20 74 68 61 74 2c 69 73 20 6d 61 3b 68 65 6d 61 74 69 3c 61 6c 6c 79     hod that,is ma;hemati<ally
20 70 72 6f 76 65 6e 20 78 6f 20 62 65 20 21 6f 74 20 63 72 61 3c 6b 65 64 20      proven xo be !ot cra<ked 
65 76 65 72 20 69 66 20 78 68 65 20 6b 65 36 20 69 73 20 6b 65 2f 74 20 73 65     ever if xhe ke6 is ke/t se
63 75 72 65 2c 20 4c 65 78 20 4d 65 20 6b 21 6f 77 20 69 66 20 26 6f 75 20 61     cure, Lex Me k!ow if &ou a
67 72 65 65 20 77 69 74 64 20 6d 65 20 74 20 20 75 73 65 20 74 37 69 73 20 65     gree witd me t  use t7is e
6e 63 72 79 70 74 69 6f 62 20 73 63 68 65 22 65 20 61 6c 77 61 26 73 2e     ncryptiob sche"e alwa&s.
```

It can't derive the key completely, so the user has to manually tweak it in about 3 spots to
determine the proper key.

Once the key is found, the key can them be converted from ASCII hexadecimal to plain ASCII text
to reveal the key:

> ALEXCTF{HERE_GOES_THE_KEY}

# Reversing challenge 2 (re2):

I ended up solving this by having the debugger tell me what the next unknown character of the
flag was each time I ran it.  I placed a breakpoint and script at the instruction that has a check
of my user input against the expected value.

```
b *0x400c75
commands
  p/c $al
  continue
  end
```
Then I keep running the challenge by typing:

```
run ALEXCTFaaa

Starting program: /home/username/ctf/alex/re2 ALEXCTFa
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$9 = 65 'A'
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$10 = 76 'L'
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$11 = 69 'E'
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$12 = 88 'X'
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$13 = 67 'C'
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$14 = 84 'T'
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$15 = 70 'F'
 
Breakpoint 6, 0x0000000000400c75 in ?? ()
$16 = 123 '{'
Better luck next time
```

Keep running the program over and over adding a character each time to the flag until you have the complete flag:

```
FLAG: ALEXCTF{W3_L0v3_C_W1th_CL45535}
```

#Reversing challenge 3 (catalyst):

The first thing you notice is that the author put a bunch of super annoying sleep calls all over
the place making the thing take forever to run.  While Binary Ninja didn't find most of the
functions that IDA Pro found for me, I used it to patch the call to sleep into just a ret
instruction so I wouldn't have to wait on it any longer.

The username is validated against what was a system of equations that you could use algebra to
solve:

```
v4 - v3 + v2 == 0x5C664B56
v3 + 3 * (v2 + v4) == 0x2E700C7B2
v2 * v3 == 0x32AC30689A6AD314
```

Where v4 is the first part of the username, v3 is the second part, and v4 is the last third.

Use the first equation to solve for v2:

> v2 = 0x5C664B56 + v3 -v4

Then plug that into the 2nd equation:

> v3 + 3 * (0x5C664B56 + v3 -v4 + v4) == 0x2E700C7B2

The variable v4 just happens to helpfully cancel itself out, leaving a simple equation to solve
and determine v3 with:

> v3 = 0x7473796c

Plug that into the 3rd equation, and solve for v2:

> v2 = 0x6f65635f

Plug v2 and v3 into the first equation and solve for v4:

> v4 = 0x61746163

> Username: catalyst_ceo

The password was validated against a pseudo-random number generated sequence of data.  The
password was divided into 3 uint32_t values, summed together, and passed to srand() as the seed of
the pseudo-random sequence.  Every 4 bytes of the password were validated by getting another
uint32_t from the PRNG, adding then adding against a constant.

I created a [program (catalyst.c)](catalyst.c) to output the password:

> Password: sLSVpQ4vK3cGWyW86AiZhggwLHBjmx9CRspVGggj

Then just put those 2 values into the program and run it to retrieve the flag.

```
./catalyst_nosleep 
 ▄▄▄▄▄▄▄▄▄▄▄  ▄            ▄▄▄▄▄▄▄▄▄▄▄  ▄       ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌▐░▌     ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░▌          ▐░█▀▀▀▀▀▀▀▀▀  ▐░▌   ▐░▌ ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌▐░▌          ▐░▌            ▐░▌ ▐░▌  ▐░▌               ▐░▌     ▐░▌          
▐░█▄▄▄▄▄▄▄█░▌▐░▌          ▐░█▄▄▄▄▄▄▄▄▄    ▐░▐░▌   ▐░▌               ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌    ▐░▌    ▐░▌               ▐░▌     ▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░▌          ▐░█▀▀▀▀▀▀▀▀▀    ▐░▌░▌   ▐░▌               ▐░▌     ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌▐░▌          ▐░▌            ▐░▌ ▐░▌  ▐░▌               ▐░▌     ▐░▌          
▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄  ▐░▌   ▐░▌ ▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░▌          
▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌     ▐░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌          
 ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀       ▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀           
Welcome to Catalyst systems
Loading..............................
Username: catalyst_ceo
Password: sLSVpQ4vK3cGWyW86AiZhggwLHBjmx9CRspVGggj
Logging in..............................
your flag is: ALEXCTF{1_t41d_y0u_y0u_ar3__gr34t__reverser__s33}
```


