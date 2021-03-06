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
parser.add_argument('-v','--verbose',default=False,action='store_true',help='Run with verbose output.')
parser.add_argument('-r','--recursive',default=False,action='store_true',help='Recursively search nested folders. Default is False. Pass flag without argument to set True.')
parser.add_argument('-d','--debug',default=False,action='store_true',help='Print out exceptions during folder operations.')
args = parser.parse_args()

def getHash(file, hashType):
    if hashType == 'MD5':
        hash = hashlib.md5(open(file, 'rb').read()).hexdigest()
    if hashType == 'SHA256':
        hash = hashlib.sha256(open(file, 'rb').read()).hexdigest()
    return hash

if args.search:
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
            for filename in glob.iglob(args.folder + '**/**', recursive=args.recursive):
                if args.verbose:
                    print(filename)
                try:
                    if not os.path.isdir(filename):
                        if args.hash == 'Both':
                            if args.search == getHash(filename, 'MD5'):
                                print(f"{filename} matched MD5 hash")
                            elif args.search == getHash(filename, 'SHA256'):
                                print(f"{filename} matched SHA256 hash")
                        else:
                            if args.search == getHash(filename, args.hash):
                                print(f"{filename} matched {args.hash} hash")
                except Exception as e:
                    print(e)
                    continue

        else:
            raise Exception('Not enough input to arguments. Need a folder(-fo) or file(-f)')
    except Exception as e:
        print(e)
else:
    try:
        if args.file:
            print(f"{args.file}")
            if args.hash == 'Both':
                print(f"\tMD5: {getHash(args.file, 'MD5')}")
                print(f"\tSHA256: {getHash(args.file, 'SHA256')}")         
            else:
                print(f"\t{args.hash}: {getHash(args.file, args.hash)}")
        elif args.folder:
            for filename in glob.iglob(args.folder + '**/**', recursive=args.recursive):
                try:
                    if not os.path.isdir(filename):
                        print('\t--' + filename)
                        if args.hash == 'Both':
                            print(f"\t\tMD5: {getHash(filename, 'MD5')}")
                            print(f"\t\tSHA256: {getHash(filename, 'SHA256')}")         
                        else:
                            print(f"\t\t{args.hash}: {getHash(filename, args.hash)}")
                    else:
                        print(filename)
                except Exception as e:
                    print(e)
                    continue
        else:
            raise Exception('Not enough input to arguments. Need a folder(-fo) or file(-f)')
    except Exception as e:
        print(e)