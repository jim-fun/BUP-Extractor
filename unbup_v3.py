#!/usr/bin/python
# UnBUP version v3.1
"""
    UnBUP Extracts Malware and Info from McAfee Quarantine File (BUP)
    Copyright (C) 2020 J. Meyer
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from itertools import izip, cycle
import sys, os
# https://bitbucket.org/decalage/olefileio_pl/downloads
import OleFileIO_PL

i = ""

print("Unbup v3.1 by J. Meyer 2020\n")

try:
    i = sys.argv[1]
except:
    print("Command format is \"unbup_v3.exe filename.bup\"")


def unbup(i):
    try:
        bup = OleFileIO_PL.OleFileIO(i)
    except:
        print("ERROR: Unable to open file or file does not exist")
        return

    dir_name = i.rstrip('.bup')
    
    try:
        print("Creating directory:", dir_name)
        os.makedirs(dir_name)
    except OSError:
        print("ERROR: Unable to create directory.  Directory might already exist or permissions are denied.")
        return
    os.chdir(dir_name)

    fileList = bup.listdir()

    #print fileList

    details = bup.openstream('Details')
    detailsEncrypted = details.read()

    file_0 = bup.openstream('File_0')
    file_0Encrypted = file_0.read()


    detailsDecrypt = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(detailsEncrypted, cycle("j")))

    #print detailsDecrypt
    d = open('details.txt', 'wb')
    d.write(detailsDecrypt)
    d.close()

    print("Extracted file: details.txt")

    # trim filename
    filenameStart = detailsDecrypt.find("OriginalName=")
    filenameEnd = detailsDecrypt.find("\n", filenameStart) - 1
    filenameStart = detailsDecrypt.rfind("\\", filenameStart, filenameEnd) + 1
    filename = detailsDecrypt[filenameStart:filenameEnd]

    file_0Decrypt = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(file_0Encrypted, cycle("j")))
    o = open(filename, 'wb')
    o.write(file_0Decrypt)
    o.close()

    print("Extracted file:", filename)

if (i!=""):
    unbup(i)

