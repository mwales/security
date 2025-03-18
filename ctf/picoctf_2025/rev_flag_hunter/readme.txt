Didn't even bother to understand how everything with the program works, but...

The line with CROWD gets input from the user, and then overwrites iteself with
the data from the user.  I wondered if you could somehow give it a crowd chant
that would cause the flag variable to be output.  I didn't see anything that
would cause that.

But I also noticed each line is split on semicolons ";".  Could we add a
semicolon and then cause something?  I noticed RETURN would parse an int from
the line to set the lip (line instruction pointer?).

Enter ;RETURN 0 as the crowd chant to get secret verse to print out.
