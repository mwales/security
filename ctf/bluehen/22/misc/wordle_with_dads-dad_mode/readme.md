# Problem (Dad Mode)

In Hard mode you get 2 guesses, no hint, 10 problems and at most 60 seconds. But I don't think you need that much time honestly...

Service: nc 0.cloud.chals.io 33282

Source: https://gist.github.com/AndyNovo/1a207eb7b6042686d6e447fa872e09e4

Author: ProfNinja

# Strategy

With all of the tools from part 1, we just need to automate the solve process.

You have to read the number of letters from the server.  Then you create a word
list of possible solutions, and pick the first choice from the set.  The server
will then tell you the number of correct letters (letters that are in the correct
position), position letters (letters that are in the wrong position).  Using that
data, you can eliminate all but 1 possbile winning solution for that round.

* Any solution that doesn't have 'correct' characters matching first guess are
  eliminated
* Any solution that has a 'position' characters that matches the first guess are
  eliminated (cause that character isn't in the right position)

These were the only 2 rules I needed, and I was able to run 10 rounds and get
the flag.  But had we needed to, could also have the following filter on the
possible solutions:

* Any solution that has a letter that is also in the first guess, but wasn't
  listed as a 'correct' or 'position' from the first guess can be eliminated.
  (That letter isn't used in the winning solution)

# Solving and Flag

My solution doesn't work all the time, mabye I'm missing a joke or often run
into a joke with a ñ (because I didn't handle it), but it worked atleast once
and I was able to score with the flag...

```
Well done! UDCTF{wh4ts_th3_be5t_th1ng_ab0ut_Sw1tzerl4nd? Dunn0_bu7_th3_flag_15_a_b1g_plu5!}
```

