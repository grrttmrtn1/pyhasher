import os
import hashlib
import argparse
from pathlib import Path
import glob
parser = argparse.ArgumentParser(description='Find and search hashes.')
parser.add_argument('-f','--file', type=str,help='File to hash. Do not use in conjuction with folder.')
parser.add_argument('-fo','--folder',type=str,help='Folder to recursively hash or search. Do not use in conjuction with file.')
parser.add_argument('-s','--search',type=str,help='Search for a hash. Pass the hash here.')
parser.add_argument('-ha','--hash',type=str,choices=['MD5','SHA256','Both'],default='Both',help='''Choose hash type. If used in 
                    conjuction with search this will speed up the process to choose. Else this will return the hash for the files passed.Default will be both.''')
parser.add_argument('-v','--verbose',type=bool,choices=[True,False],default=False,help='Run with verbose output.')
parser.add_argument('-r','--recursive',default=False,action='store_true',help='Recursively search nested folders. Default is False. Pass flag without argument to set True.')
args = parser.parse_args()


if args.search:
    print('searching')
    try:
        if args.file:
            if args.hash == 'MD5':
                if args.search == hashlib.md5(open(args.file, 'rb').read()).hexdigest():
                    print(args.file + ' matched MD5 hash')
                else:
                    print(args.file + ' did not match hash provided')
            if args.hash == 'SHA256':
                if args.search == hashlib.sha256(open(args.file, 'rb').read()).hexdigest():
                    print(args.file + ' matched SHA256 hash')
                else:
                    print(args.file + ' did not match hash provided')
            if args.hash == 'Both':
                if args.search == hashlib.md5(open(args.file, 'rb').read()).hexdigest():
                    print(args.file + ' matched MD5 hash')
                elif args.search == hashlib.sha256(open(args.file, 'rb').read()).hexdigest():
                    print(args.file + ' matched SHA256 hash')
                else:
                    print(args.file + ' did not match hash provided')
        elif args.folder:
            print('folder search')
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