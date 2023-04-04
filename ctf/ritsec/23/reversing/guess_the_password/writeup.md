After analyzing the code, I realized that the password it asks the user for
only depends on non-secret data.  There is also a hint that the password
is 8 digits.

So I add a small password cracking routine to the python source code for
server.py.  I loop over all numubers 0 - 100000000, convert each number
to a string, and then determine if that number will pass the password
check check_input.

'''
debug_print("Start cracking")
for simplePass in range(0,100000000):
   passStr = "{}".format(simplePass)
   if self.encoder.check_input(passStr):
      print("Pass = {}".format(passStr))
debug_print("Done cracking")
'''

I run my custom server.py and after maybe a minute, it spits out the following:

'''
Start cracking
Waiting for client
Pass = 54744973
'''

So I connect to the real server with the flag and try to provide the same
password:

'''
user@ctf2204:~/checkouts/security/ctf/ritsec/23/reversing/guess_the_password$ nc guessthepassword.challenges.ctf.ritsec.club 1337
Enter the passcode to access the secret: 
54744973
RS{'PyCr@ckd'}

Closing connection...
'''
