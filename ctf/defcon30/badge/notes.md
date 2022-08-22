9 = 0x100
8 = 0x80
7 = 0x40
6 = 0x20
5 = 0x10
4 = 0x08
3 = 0x04
2 = 0x02
1 = 0x01
0 = 0x200


     ─────
    /     \
   /  ┌─┐  \
  /   └─┘   \
 │           │
 │  ┌─┐ ┌─┐  │
 │  │1│ │a│  │
 │  └─┘ └─┘  │
 │           │
 │  ┌─┐ ┌─┐  │
 │  │2│ │9│  │
 │  └─┘ └─┘  │
 │           │
 │  ┌─┐ ┌─┐  │
 │  │3│ │8│  │
 │  └─┘ └─┘  │
 │           │
 │  ┌─┐ ┌─┐  │
 │  │4│ │7│  │
 │  └─┘ └─┘  │
 │           │
 │  ┌─┐ ┌─┐  │
 │  │5│ │6│  │
 │  └─┘ └─┘  │
 │           │
 │ ┌─┐   ┌─┐ │
 │ └─┘   └─┘ │
 │           │
 └───────────┘

Debug 2wire SWD

Pin 2 = SWDIO
Pin 4 = SWCLK


pins 5, 3, 9 and connected to J1 2



SAO Connector

(top of badge / power connector)

1 2 3
4 5 6

1 = 3.3V
4 = Ground
2 = GPIO 20
5 = GPIO 21

2 = JP1 
5 = JP2

Winbond
@25Q16JV

top of board



8  7  6  5


1  2  3  4



Windbond pinout
1 = CS-bar
2 = DO
3 = WP bar
4 = GND

5 = DI
6 = CLK
7 = HOLD bar or RESET bar
8 = VCC

J1 is a 3.3V power connector, it's connected to battery positive and ground


Keyboard:

 2 4   7 9
1 3 4 6 8 0

>>> badgenum = 3681949487
>>> alice = badgenum ^ 2784639871
>>> print(alice)
2123115600
>>> bob = badgenum ^ 0xe35c2742
>>> print(bob)
942289005
>>> dan = 0x87e35d46 ^ badgenum
>>> print(dan)
1553287785
>>> eve = badgenum ^ 0x5acd14f9
>>> print(eve)
2176517078
>>> trevor = badgenum ^ 0xabde1fcf
>>> print(trevor)
1890060512

From RP2040 manual.
 (I see addr + 0x1000 alot)

Each peripheral register block is allocated 4kB of address space, with registers accessed using one of 4 methods,
selected by address decode.
• Addr + 0x0000 : normal read write access
• Addr + 0x1000 : atomic XOR on write
• Addr + 0x2000 : atomic bitmask set on write
• Addr + 0x3000 : atomic bitmask clear on write

dmesg output generated from badge

[1125811.847556] usb 1-4.1: USB disconnect, device number 64
[1125812.407672] usb 1-4.1: new full-speed USB device number 65 using xhci_hcd
[1125812.851663] usb 1-4.1: New USB device found, idVendor=dc30, idProduct=dc30, bcdDevice= 1.00
[1125812.851665] usb 1-4.1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[1125812.851666] usb 1-4.1: Product: DC30-DB76172F
[1125812.851667] usb 1-4.1: Manufacturer: MK Factor
[1125812.851668] usb 1-4.1: SerialNumber: E6619864DB76172F

Notes for the original song / challenge 1:

12 face keys
octave 1 = 0x00 - 0x0b
octave 2 = 0x0c - 0x17
octave 3 = 0x18 - 0x23
octave 4 = 0x24 - 0x2f
octave 5 = 0x30 - 0x3b
octave 6 = 0x3c - 0x47

Hex String / Ascii string that is checked for completing challenge 1:

10002df0  void check_song_played_for_chal1(int32_t arg1)

10002df0  {
10002e02      for (int32_t r3 = 0; r3 <= 0x2c; r3 = (r3 + 1))
10002df6      {
10002dfc          *(int8_t*)(0x200063d8 + r3) = *(int8_t*)(r3 + 0x200063d9);
10002dfa      }
10002e08      g_num_elements_in_63d8_array = ((int8_t)arg1);
10002e0a      int32_t r3_1 = 0;
10002e0e      while (true)
10002e0e      {
10002e0e          if (r3_1 > 0x2d)
10002e0c          {
10002e24              g_chals_completed = 1;
10002e26              uint32_t r6;
10002e26              sub_10002218(r6);
10002e2a              challenge_complete();
10002e2a              break;
10002e2a          }
10002e1a          if (((uint32_t)*(int8_t*)(0x200063d8 + r3_1)) != ((uint32_t)*"C@><>@C@><>@C@CE@EC@><C@><>@C@><…"[r3_1]))
10002e16          {
10002e1a              break;
10002e1a          }
10002e1c          r3_1 = (r3_1 + 1);
10002e1c      }
10002e1c  }

That mess of ascii is the following in hex:

C@><>@C@><>@C@CE@EC@><C@><>@C@><>@>@C@CE@EGDB@

 43 40 3e 3c 3e 40 43 40 3e 3c 3e 40 43 40 43 45  C@><>@C@><>@C@CE
 40 45 43 40 3e 3c 43 40 3e 3c 3e 40 43 40 3e 3c  @EC@><C@><>@C@><
 3e 40 3e 40 43 40 43 45 40 45 47 44 42 40        >@>@C@CE@EGDB@




The face keys of the keyboard (there are 12 keys)

C, C#, D, D#, E, F, F#, F, G#, A, A#, B

For the octave that all the keys are in, the keys would be


C, C#, D, D#, E, F, F#, G, G#, A, A#, B
3C 3D  3E 3F  40 41 42  43 44  45 46  47

Replacing the hex with the keys for the keyboard


 G  E  D  C  D  E  G  E  D  C  D  E  G  E  G  A
 E  A  G  E  D  C  G  E  D  C  D  E  G  E  D  C
 D  E  D  E  G  E  G  A  E  A  B  G# F# E


 G  E  D  C
 D  E  G  E
 D  C  D  E
 G  E  G  A
 E  A  G  E
 D  C  G  E
 D  C  D  E
 G  E  D  C
 D  E  D  E
 G  E  G  A
 E  A  B  G#
 F# E





