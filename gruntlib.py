# Startup from single-user installation
# Copyright (C) 2002 John Goerzen
# <jgoerzen@complete.org>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import binascii, os, pwd, time, md5, fcntl, re
from ConfigParser import ConfigParser

def encode(binary):
    return binascii.b2a_base64(binary).strip()

def decode(ascii):
    return binascii.a2b_base64(ascii)

def copy(infile, outfile):
    while 1:
        data = infile.read(10240)
        if not len(data):
            return
        outfile.write(data)

def getheaders(user, mode = None, dest = None, secure = 0):
    retval = getheader(secure) + "\n"
    retval += ":USER:%s\n" % encode(user)
    if not secure:
        retval += ":DATA:\n"
        return retval
    retval += getsenderstr()
    retval += getrandstr()
    retval += ":MODE:%s\n" % encode(mode)
    retval += ":DEST:%s\n" % encode(dest)
    retval += ":DATA:\n"
    return retval

def getheader(secure = 0):
    if (secure):
        securestr = 'S'
    else:
        securestr = 'I'
    add = ''
    if not secure:
        add = 'IN'
    return ':GRUNT:%sSECUREHEADER:FORMAT-1%s:' % (add, securestr)
    
def getsenderstr():
    return ":SENDER:%s\n" % \
                  encode("%s:%d:%d" % \
                         (pwd.getpwuid(os.getuid())[0],
                          os.getpid(),
                          long(time.time())))

def getrandstr():
    rndfd = open("/dev/urandom", "rb")
    rnddata = ''
    while len(rnddata) < 256:
        rnddata += rndfd.read(256 - len(rnddata))
    rndfd.close()
    return ":RANDOM:%s\n" % encode(rnddata)

def readwithcheck(fd, linestart):
    line = fd.readline(1024).strip()
    if not line.startswith(linestart):
        raise ValueError, "Line %s did not begin with %s" % \
              (repr(line), repr(linestart))
    return decode(line[len(linestart):])

def getuserhome():
    return pwd.getpwuid(os.getuid())[5]

def getgrunthome():
    return getuserhome() + '/.grunt'

def getgruntwork():
    return getgrunthome() + '/work'

def getusername():
    return pwd.getpwuid(os.getuid())[0]

def sanitizeenviron():
    os.environ['HOME'] = getuserhome()
    os.environ['LOGNAME'] = getusername()
    os.environ['USER'] = getusername()

def findfirstheader(fd):
    while 1:
        line = fd.readline(1024)
        if not len(line):
            raise ValueError, "Could not find GRUNT header; aborting."
        line = line.strip()
        if line == getheader(0):
            return

def headercheck(fd, secure = 0):
    readwithcheck(fd, getheader(secure))
    
def usernamecheck(username):
    if pwd.getpwuid(os.getuid())[0] != username:
        raise ValueError, "Could not change to user %s" % username

def getvalidsigsfile():
    return getgrunthome() + '/validsigs.txt'

def checkforvalidsigsfile():
    if not os.path.isfile(getvalidsigsfile()):
        raise ValueError, "File %s does not exist" % getvalidsigsfile()

def makegruntwork():
    if not os.path.isdir(getgruntwork()):
        os.mkdir(getgruntwork(), 0700)

def gettmpfilename():
    return getgruntwork() + '/workfile-%d-%s' % (os.getpid(), time.time())

def scanfileforlines(file, lines):
    fd = open(file)
    for line in fd.xreadlines():
        if line[0] == '#':
            continue
        if line.strip() in lines:
            fd.close()
            return 1
    fd.close()
    return 0

def computemd5(fd):
    thismd5 = md5.md5()
    while 1:
        chunk = fd.read(10240)
        if not len(chunk):
            break
        thismd5.update(chunk)
    return thismd5.hexdigest()

def openwithlock(filename):
    fd = os.open(filename, os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return os.fdopen(fd, 'r+')

def transportopen(dest):
    if dest.find('!') != -1:
        return uucpopen(dest)
    elif dest.find('@') != -1:
        return emailopen(dest)
    else:
        raise ValueError, "Destination %s is not a valid e-mail address or UUCP path" % dest

def uucpopen(dest):
    machine, user = re.search('^(.+)!([^!]+)$', dest).groups()
    outfile = os.popen("uux -z - '%s!gruntreceive-uucp'" % machine, 'w')
    return (user, outfile)

EMAILSUBJECT = '---GRUNT_SIGNED_JOB_EMAIL---'

def emailopen(dest):
    user,machine = re.search('^([^@]+)@(.+)$', dest).groups()
    outfile = os.popen("mail -s '%s' -a 'X-Grunt-Request: yes' '%s'" %\
                       (EMAILSUBJECT, dest), 'w')
    return (user, outfile)

def addcommonoptions(parser):
    #parser.add_option('-s', '--status-to', dest='status',
    #                  metavar='EMAIL_ADDRESS',
    #                  help = """Delivers output or command status
    #                  from a successful invocation to EMAIL_ADDRESS
    #                  (UUCP users can specify a bang path here).""")
    parser.add_option("-e", "--encrypt", dest = 'encrypt',
                      metavar='RECIPIENT', help = 'Encrypt data to RECIPIENT')


def getconfig():
    config = ConfigParser()
    if os.path.isfile(getgrunthome() + '/config'):
        config.read(getgrunthome() + '/config')
    return config

def getencryptoptions(options, config, dest):
    if options.encrypt:
        print "Data will be encrypted as specified on command line."
        return ['--encrypt', '--recipient', options.encrypt]
    if config.has_option('destination ' + dest, 'encryptkey'):
        print "Data will be encrypted as specified in config file."
        return ['--encrypt', '--recipient',
                config.get('destination ' + dest, 'encryptkey')]
    print "Data will not be encrypted for transit, but will be signed."
    return []
    
