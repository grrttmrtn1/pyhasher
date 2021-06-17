import os
import hashlib
import argparse
from pathlib import Path
import glob
parser = argparse.ArgumentParser(description='Find and search hashes.')
parser.add_argument('-f','--file', type=str,help='File to hash. Do not use in conjuction with folder.')
parser.add_argument('-fo','--folder',type=str,help='Folder to recursively hash or search. Do not use in conjuction with file. If searching a folder non recursively ensure that you do not add os.sep i.e. "/" or it will ignore files in the root dir of your search. Adding "/" will search only subdirectories' )
parser.add_argument('-s','--search',type=str,help='Search for a hash. Pass the hash here.')
parser.add_argument('-ha','--hash',type=str,choices=['MD5','SHA256','Both'],default='Both',help='''Choose hash type. If used in 
                    conjuction with search this will speed up the process to choose. Else this will return the hash for the files passed.Default will be both.''')
parser.add_argument('-v','--verbose',type=bool,choices=[True,False],default=False,help='Run with verbose output.')
parser.add_argument('-r','--recursive',default=False,action='store_true',help='Recursively search nested folders. Default is False. Pass flag without argument to set True.')
args = parser.parse_args()

def getHash(file, hashType):
    if hashType == 'MD5':
        hash = hashlib.md5(open(file, 'rb').read()).hexdigest()
    if hashType == 'SHA256':
        hash = hashlib.sha256(open(file, 'rb').read()).hexdigest()
    return hash

if args.search:
    print('searching')
    try:
        if args.file:
            if args.hash == 'Both':
                if args.search == getHash(args.file, 'MD5'):
                    print(args.file + ' matched MD5 hash')
                elif args.search == getHash(args.file, 'SHA256'):
                    print(args.file + ' matched SHA256 hash')
                else:
                    print(args.file + ' did not match hash provided')
            else:
                if args.search == getHash(args.file, args.hash):
                    print(f"{args.file} matched {args.hash} hash")
                else:
                    print(f"{args.file}did not match hash provided")

        elif args.folder:
            print('folder search')
            for filename in glob.iglob(args.folder + '**/**', recursive=args.recursive):
                if not os.path.isdir(filename):
                    if args.hash == 'Both':
                        if args.search == getHash(filename, 'MD5'):
                            print(f"{filename} matched MD5 hash")
                        elif args.search == getHash(filename, 'SHA256'):
                            print(f"{filename} matched SHA256 hash")
                    else:
                        if args.search == getHash(filename, args.hash):
                            print(f"{filename} matched {args.hash} hash")

        else:
            raise Exception('Not enough input to arguments. Need a folder(-fo) or file(-f)')
    except Exception as e:
        print(e)
else:
    try:
        if args.file:
            print(args.file)
            print('file')
            if args.hash == 'MD5' or args.hash == 'Both':
                print('\tMD5: ' + hashlib.md5(open(args.file, 'rb').read()).hexdigest())
            if args.hash == 'SHA256' or args.hash == 'Both':
                print('\tSHA256: ' + hashlib.sha256(open(args.file, 'rb').read()).hexdigest())
        elif args.folder:
            print('folder')
            print(args.recursive)
            for filename in glob.iglob(args.folder + '**/**', recursive=args.recursive):
                if not os.path.isdir(filename):
                    print('\t' + filename)
                    if args.hash == 'MD5' or args.hash == 'Both':
                        print('\t\tMD5: ' + hashlib.md5(open(filename, 'rb').read()).hexdigest())
                    if args.hash == 'SHA256' or args.hash == 'Both':
                        print('\t\tSHA256: ' + hashlib.sha256(open(filename, 'rb').read()).hexdigest())
                else:
                    print(filename)
        else:
            raise Exception('Not enough input to arguments. Need a folder(-fo) or file(-f)')
    except Exception as e:
        print(e)