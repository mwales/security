# Crypto challenge 1:

Big blob of text that was "ZERO ONE ZERO ..."

Wrote a program (decoder.cpp) to decode it into ASCII...

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

I created a program (catalyst.c) to output the password:

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


