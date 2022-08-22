#!/usr/bin/env python3

f = open("./More Sense", "r")
fd = f.read()
f.close()

print(fd)

morseCode = { ".-"   : "A",
              "-..." : "B",
              "-.-." : "C",
              "-.."  : "D",
              "."    : "E",
              "..-." : "F",
              "--."  : "G",
              "...." : "H",
              ".."   : "I",
              ".---" : "J",
              "-.-"  : "K",
              ".-.." : "L",
              "--"   : "M",
              "-."   : "N",
              "---"  : "O",
              ".--." : "P",
              "--.-" : "Q",
              ".-."  : "R",
              "..."  : "S",
              "-"    : "T",
              "..-"  : "U",
              "...-" : "V",
              ".--"  : "W",
              "-..-:": "X",
              "-.--" : "Y",
              "--..:": "Z",

              "-----"   : "0",
              ".----"   : "1",
              "..---"   : "2",
              "...--"   : "3",
              "....-"   : "4",
              ".....":  "5",
              "-...."  : "6",
              "--..."   : "7",
              "---.."   : "8",
              "----.": "9",

              ".-.-.-"  : ".",
              "--..--"  : ",",
              "..--.."  : "?",
              ".----."  : "'",
              "-.-.--"  : "!",
              "-..-." : "/",
              "-.--."   : "(",
              "-.--.-"  : ")",
              ".-..."   : "&",
              "---..."  : ":",
              "-.-.-."  : ";",
              "-...-"  : "=",
              ".-.-."   : "+",
              "-....-" : "-",  
              "..--.-"  : "_",
              ".-..-." : '"', 
              "...-..-" : "$",
              ".--.-." : "@",
              "..-.-"   : "¿",
              "--...-" : "¡",
              }

morse = fd.replace("B",".").replace("A","-")
morse = fd.replace("B","-").replace("A",".")

print(morse)

bigString = ""
for singleLetters in morse.split():
    decodeLetter = morseCode.get(singleLetters, "?")
    bigString += decodeLetter

    print("{} => {} ".format(singleLetters, decodeLetter))

print("bigString = {}".format(bigString))
