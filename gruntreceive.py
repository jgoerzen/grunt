#!/usr/bin/python2.2

import sys, re, os, pwd
from sys import stdin, stdout
import pyme, pyme.core

"""File format:

Plain:
:GRUN:INSECUREHEADER:FORMAT-1I:
:USER:username
:DATA:

Signed/Encrypted:
:GRUN:SECUREHEADER:FORMAT-1S:
:USER:username
:MODE:mode
:DEST:destination
:DATA:
--data follows here--

*DATA MUST OCCUR IN THIS ORDER, NO UNSPECIFIED WHITESPACE PERMITTED*

Where:

  "username" is the name of the user to run as
  "mode" is one of:
     EXEC -- execute a command -- attached data to be used as stdin
     PUT  -- copy a file into place
  "destination" is:
     a filename (for PUT mode)
     a command (for EXEC mode)

All replaceable data (the lowercase stuff) must be base64-encoded.

No line, post-base64ing, may exceed 1023 characters.

     """

# Start processing.

assert stdin.readline(1024).strip() == ':GRUN:INSECUREHEADER:FORMAT-1I:'
username = re.search('^:USER:(.+)$', stdin.readline(1024).strip()).group(1)
username = base64.decodestring(username)
if pwd.getpwuid(os.getuid())[0] != username:
    destuid, destgid = pwd.getpwnam(username)[2:4]
    os.setgroups([])
    os.setregid(destgid)
    os.setreuid(destuid)
    
