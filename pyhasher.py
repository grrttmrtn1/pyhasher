import os
import hashlib
import argparse
parser = argparse.ArgumentParser(description='Find and search hashes')
parser.add_argument('-f','--file', type=str,help='File to hash. Do not use in conjuction with folder.')
parser.add_argument('-fo','--folder',type=str,help='Folder to recursively hash or search. Do not use in conjuction with file.')
parser.add_argument('-s','--search',type=str,help='Search for a hash. Pass the hash here')
parser.add_argument('-ha','--hash',type=str,choices=['MD5','SHA256','Both'],default='Both',help='''Choose hash type. If used in 
                    conjuction with search this will speed up the process to choose. Else this will return the hash for the files passed.Default will be both''')
parser.add_argument('-v','--verbose',type=bool,choices=[True,False],default=False,help='Run with verbose output')
args = parser.parse_args()


if args.search:
    print('searching')
    try:
        if args.file:
            print('test')
        elif args.folder:
            print('test')
        else:
            raise Exception('Not enough input to arguments. Need a folder(-fo) or file(-f)')
    except Exception as e:
        print(e)
else:
    try:
        if args.file:
            print(args.file)
            if args.hash == 'MD5' or args.hash == 'Both':
                print('\tMD5: ' + hashlib.md5(open(args.file, 'rb').read()).hexdigest())
            if args.hash == 'SHA256' or args.hash == 'Both':
                print('\tSHA256: ' + hashlib.sha256(open(args.file, 'rb').read()).hexdigest())
        elif args.folder:
            for root, dirs, files in os.walk(args.folder):
                path = root.split(os.sep)
                print((len(path) - 1) * '---', os.path.basename(root))
                for file in files:
                        print(len(path) * '---', file)
                        if args.hash == 'MD5' or args.hash == 'Both':
                            print('\tMD5: ' + hashlib.md5(open(args.file, 'rb').read()).hexdigest())
                        if args.hash == 'SHA256' or args.hash == 'Both':
                            print('\tSHA256: ' + hashlib.sha256(open(args.file, 'rb').read()).hexdigest())
        else:
            raise Exception('Not enough input to arguments. Need a folder(-fo) or file(-f)')
    except Exception as e:
        print(e)