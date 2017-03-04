I think I can do a padding oracle attack on this.

Agent number: 1234567890
8f636866f28cab6eec8c27dad3a50af4963801dbfc25ed7eab5656c1eacd34970bdd27c51e8d3bfc10c5c9a5e11f518601a40c5e9ab106dbc6c30dc3032ee244825582c3a7d4204e299ce21c168ed077
160 characters long = 5-blocks of AES encryption


Agent number: 12345678901
8f636866f28cab6eec8c27dad3a50af484b98170ff7ad1cc725664adb73585f088cb3078a2e04a92b0c7a197f70a6699eb6d33b09879bf12ab9bd66d131121f5c349e706ac03e4f4c858d1ec9e7005dd8b1f62020ab4096b07e7f9a0839a5b40
192 characters long = 6-blocks of AES encryption

a g e n t _ 1 2 3 4 5 6 7 8 9 0 1 _ w a n t s _ t o _ s e e _ 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 f f f f f f f f f f f f f f f f

So the flag must be 49 bytes long.  Lengthening the message 1 block at a time till the padding pops out another block, means that block must be all 0x10 for padding.

That should be easy to test, create an agent name that is ' ' * 10 + '\x01' + '\x00' * 15

Gives us:
1a51ae2a56741934defb2fb5aad93d708b1f62020ab4096b07e7f9a0839a5b40963801dbfc25ed7eab5656c1eacd34970bdd27c51e8d3bfc10c5c9a5e11f518601a40c5e9ab106dbc6c30dc3032ee244825582c3a7d4204e299ce21c168ed077

The block of interest:
1a51ae2a56741934defb2fb5aad93d70
8b1f62020ab4096b07e7f9a0839a5b40 <-- Block of padding.  It does match the padding at the end of the message we received that we think is all padding!
963801dbfc25ed7eab5656c1eacd3497
0bdd27c51e8d3bfc10c5c9a5e11f5186
01a40c5e9ab106dbc6c30dc3032ee244
825582c3a7d4204e299ce21c168ed077

Wrote a program then that would reveal one single byte from flag.  We can guess all the ASCII
printable flag bytes in a seperate block and see which block matches the missing unknown byte.

Keep doing this over and over to reveal a new byte of flag each attempt, until the entire flag
is known.

Flag Known=527ef19c76273c0c813f54b8f974cd10_ECB_is_the_w0rst

