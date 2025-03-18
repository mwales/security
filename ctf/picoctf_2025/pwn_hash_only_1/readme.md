I noticed that that flaghasher binary has set-uid bit set and will run as root
(and why it can read the flag in root folder).  No input is read from the
user so it didn't seem like a likely target for exploitation.

Opening up flaghasher with Binary Ninja reveals that it calls md5sum using the
system() function.  Looking at the permissions for md5sum shwo that is
writeable by everyone.  I simply copied over the md5sum program with the cat
program, so now it just dumps the contents of the flag file.

picoCTF{redacted}
