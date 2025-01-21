# Program Purpose

This script can be used to evaluate the output from a programming challenge.
As long as you have a single possible good output, you can use this script to
evaluate the output for correctness and can reveal a hidden flag to the user
when they have the correct output.

# Instuctions

1. Create a flag.txt file that will store the secret flag.  The flag has to be
   shorter in length than a sha512 checksum
2. You need to have an example of what the correct output would be from the
   user.  The name of this file isn't important. We'll call it the challenge
   output file.
3. Run the craft_generic_judge.py program, provide the challenge output file as
   standard input.  The program will output a new script that we will call the
   judgement script.
4. Distribute the judgement script to the players.
5. The players should send pass their program's output to the judgement script
   as it's standard input.  The judgement script will tell them what line they
   have wrong, or tell them the output is correct and give them the secret
   flag.

## Examples

### Example Challenge:

Write a program that accepts a list of positive integers, one number per line.  For each
number the program will output the word for number in each place.  The program should
exit after it receives the number zero.

Example input

```
123
88
0
```

Example output
```
one two three
eight eight
zero
```

We have an example [challenge input](example/challenge_input.txt), and example
[solution](example/solution.py) to the challenge in the example folder.

## Example instructions

To create the judgement script:

```
$ cd example
$ echo "example_ctf{secret_flag_text}" > flag.txt
$ cat challenge_input.txt | ./solution | ../craft_generic_judge.py > judgement.py
Judge Script Output Complete
$ chmod a+x judgement.py
```

How a user can check their output:

```
$ cat challenge_input.txt | ./solution | ./judgement.py
Congrats!
example_ctf{secret_flag_text}  
$
```

If we alter the solution.py file to output the word niner instead of the word
nine, we get the following output:

```
$ cat challenge_input.txt | ./solution.py | ./judgement.py 
Output incorrect
Line 7: niner two niner
$
```


