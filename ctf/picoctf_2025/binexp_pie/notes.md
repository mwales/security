Win function is at 0x12a7.  The main function reads a hex integer from the user
and then jumps to the address given by the user as if it were a function.

Putting 0x12a7 in for the function address just ends up causing a segfault.
Starting the binary in a debugger (or paying attention to the output and not
blindly ignoring it like I did) will show you that the program uses address 
randomization.  So given the address of main, figure out the difference between
the win and main function and add that to the main function address:

```
Address of main: 0x5a08d0e0033d
```

So in python3 console:

```
>>> hex(0x5a08d0e0033d - 0x133d + 0x12a7)
'0x5a08d0e002a7'
```

Entering that into the program to reveal the flag:

```
Address of main: 0x5a08d0e0033d
Enter the address to jump to, ex => 0x12345: 0x5a08d0e002a7
Your input: 5a08d0e002a7
You won!
picoCTF{redacted}
```

