#!/usr/bin/python2.2

import sys, re, os, pwd, time, base64
from sys import stdin, stdout
import pyme, pyme.core
import GnuPGInterface

"""File format:

Plain:
:GRUNT:INSECUREHEADER:FORMAT-1I:
:USER:username
:DATA:

Signed/Encrypted:
:GRUNT:SECUREHEADER:FORMAT-1S:
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

def copy(infile, outfile):
    while 1:
        data = infile.read(10240)
        if not len(data):
            return
        outfile.write(data)
    

# Start processing.

assert stdin.readline(1024).strip() == ':GRUNT:INSECUREHEADER:FORMAT-1I:'
username = re.search('^:USER:(.+)$', stdin.readline(1024).strip()).group(1)
username = base64.decodestring(username)
if pwd.getpwuid(os.getuid())[0] != username:
    destuid, destgid = pwd.getpwnam(username)[2:4]
    os.setgroups([])
    os.setregid(destgid)
    os.setreuid(destuid)
    
assert pwd.getpwuid(os.getuid())[0] == username,\
       "Could not change to correct user"

HOMEDIR = pwd.getpwuid(os.getuid())[5] + '/.grunt'
WORKDIR = HOMEDIR + '/work'
assert os.path.isfile(HOMEDIR + '/validsigs.txt'),\
       "File %s does not exist" % (HOMEDIR + '/validsigs.txt')
os.chdir(HOMEDIR)

if not os.path.isdir(WORKDIR):
    os.mkdir(WORKDIR, 0700)

tmpfilename = WORKDIR + '/workfile-%d-%s' % (os.getpid(), time.time())
gnupg = GnuPGInterface.GnuPG()
gnupg.options.meta_interactive = 0
process = gnupg.run(['--decrypt', '--output', tmpfilename],
                    create_fhs=['status', 'stdin'])
if (os.fork() == 0):
    # Copy process.
    copy(stdin, process.handles['stdin'])
    stdin.close()
    process.handles['stdin'].close()
    process.handles['status'].close()
    sys.exit(0)
else:
    stdin.close()
    process.handles['stdin'].close()
goodsig = None
signatory = None
while 1:
    status = process.handles['status'].readline()
    if len(status) == 0:
        break
    statuswords = status.strip().split(' ')
    if statuswords[1] == 'GOODSIG':
        goodsig = 1
        signatory = statuswords[2]
    if statuswords[1] == 'BADSIG':
        goodsig = 0
        
if not goodsig:
    try:
        os.unlink(tmpfilename)
    except OSError:
        pass
    raise ValueError, "FAILURE: no signature detected!"

# Now, check to see if this signature is in the user's list of acceptable ones.

shortsignatory = signatory[-8:]
foundvalid = 0

gsf = open(HOMEDIR + '/validsigs.txt')
for line in gsf.readlines():
    if line.strip() == shortsignatory or line.strip() == signatory:
        foundvalid = 1
        break
gsf.close()

if not foundvalid:
    try:
        os.unlink(tmpfilename)
    except OSError:
        pass
    raise ValueError, "FAILURE: Key %s (%s) not found in list of valid keys."%\
          (signatory, shortsignatory)

# Good sig.  Process the data.

datafile = open(tmpfilename)

try:
    assert datafile.readline(1024).strip() == ':GRUNT:SECUREHEADER:FORMAT-1S:'
    susername = re.search('^:USER:(.+)$', datafile.readline(1024).strip()).group(1)
    susername = base64.decodestring(susername)
    assert susername == username, 'FAILURE: secure packet username %s differs from regular username %s' % (susername, username)
    
    mode = re.search('^:MODE:(.+)$', datafile.readline(1024).strip()).group(1)
    mode = base64.decodestring(mode)
    
    dest = re.search('^:DEST:(.+)$', datafile.readline(1024).strip()).group(1)
    dest = base64.decodestring(dest)

    assert datafile.readline(1024).strip() == ':DATA:'

    if mode == 'EXEC':
        outputfd = os.popen(dest, 'w')
    elif mode == 'PUT':
        outputfd = open(dest + '.gruntput', 'wb')
    copy(datafile, outputfd)
    outputfd.close()
    if mode == 'PUT':
        os.rename(dest + '.gruntput', dest)
finally:
    datafile.close()
    os.unlink(tmpfilename)
