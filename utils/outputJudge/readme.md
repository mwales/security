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

# How does this work

For each line of the expected output, we strip off leading/trailing whitespace
to help alleviate problems with Windows / Linux line ending differences. Then
for each line we compute an expected sha256 sum of the text for that line.

The verification script can then check each line to determine where the first
line of output that is wrong to tell the user that need to check how that test
case worked, or line of output was created.

If the correct number of lines are present, and all of them are correct (pass
the sha256 checksum verification), we create a sha512 checksum of the entire
output together.  This checksum is used as a one-time-pad to encrypt and
decrypt the secret flag.  If any single output character of the output was
wrong, this step would decrypt to garbage, but we already know the output is
correct because we checked each line.

The rest of the challenge for this process is create a crafting script that
helps automate all of this.  There is a script called the template, it is
basically included as a base64 blob of text in the crafting script.

