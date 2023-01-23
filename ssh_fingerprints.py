#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
from re import match
from subprocess import CalledProcessError, check_output
from sys import stdout

parser = ArgumentParser()
parser.add_argument('input', nargs='*', help='Specific key files to print; by default, ssh-agent keys are printed')
parser.add_argument('-a', '--all', action='store_true', help='When set, show all discovered pubkeys (from --include paths; default: only show keys added to ssh-agent)')
parser.add_argument('-i', '--include', nargs='*', help='Files or directories to include in the search for public keys; default: $HOME/.ssh')
parser.add_argument('-M', '--no-md5', action='store_true', help='When set, exclude MD5 fingerprints from the output')
parser.add_argument('-s', '--sha256', action='store_true', help='When set, include SHA256 fingerprints in the output (by default, only MD5 fingerprints are shown')
parser.add_argument('-t', '--field-separator', default='\t', metavar='char', help='Use `char` as a field separator character (default: <TAB>)')
args = parser.parse_args()
all = args.all
inputs = args.input
if all and inputs:
    raise ValueError(f"Specify at most one of <input...>, --all")
includes = [Path.home() / '.ssh'] + [ Path(path) for path in (args.include or []) ]
md5 = not args.no_md5
sha256 = args.sha256
if not md5 and not sha256:
    sha256 = True
field_separator = args.field_separator


def lines(*args, rm_empty_trailing_line=True):
    cmd = [ str(arg) for arg in args if arg is not None ]
    try:
        lines = check_output(cmd).decode().split('\n')
    except CalledProcessError:
        return []
    if rm_empty_trailing_line and lines and not lines[-1]:
        lines = lines[:-1]
    return lines


FINGERPRINT_REGEX = r'^(?P<bits>\d+) (?P<hash_fn>SHA256|MD5):(?P<hash>[\w/\+:]+) (?P<comment>.*) \((?P<type>[A-Z\d]+)\)$'


def parse_fingerprint_line(line):
    m = match(FINGERPRINT_REGEX, line)
    if not m:
        raise ValueError(f'Unrecognized fingerprint line: {line}')
    d = m.groupdict()
    d['bits'] = int(d['bits'])
    d[d['hash_fn'].lower()] = d['hash']
    del d['hash']
    del d['hash_fn']
    return d


if md5:
    agent_md5s = [
        parse_fingerprint_line(line)
        for line in lines('ssh-add', '-l', '-E', 'md5')
    ]
else:
    agent_md5s = []

if sha256:
    agent_sha256s = [
        parse_fingerprint_line(line)
        for line in lines('ssh-add','-l','-E','sha256')
    ]
else:
    agent_sha256s = []

pubkey_paths = [
    path
    for include in includes
    for path in (
        list(include.glob('*.pub'))
        if include.is_dir()
        else [ include ]
    )
] + inputs


def merge(o, *dicts, copy=True):
    if not dicts: return o
    ( nxt, *rest ) = dicts
    if copy: o = o.copy()
    for k,v in nxt.items():
        if k in o:
            if o[k] != nxt[k]:
                raise ValueError(f'Conflicting key {k} ({o[k]} vs. {nxt[k]}): {o}, {nxt}')
        else:
            o[k] = nxt[k]
    return merge(o, *rest, copy=False)


def get_fingerprint_line(path, hash):
    [line] = lines('ssh-keygen', '-l', '-E', hash, '-f', path)
    d = parse_fingerprint_line(line)
    d['path'] = path
    return d


def read_pubkey(pubkey_path):
    return merge(*(
        ([ get_fingerprint_line(pubkey_path, 'md5') ] if md5 else []) +
        ([ get_fingerprint_line(pubkey_path, 'sha256') ] if sha256 else []) +
        [{ 'agent': False }]
    ))


pubkeys = [
    read_pubkey(pubkey_path)
    for pubkey_path in pubkey_paths
]

pubkeys_by_md5 = {d['md5']: d for d in pubkeys if 'md5' in d}
pubkeys_by_sha256 = {d['sha256']: d for d in pubkeys if 'sha256' in d}
pubkeys_by_path = {d['path']: d for d in pubkeys}

if inputs:
    pubkeys = [key for key in pubkeys if key['path'] in inputs]
    pubkeys_by_md5 = {k: v for k, v in pubkeys_by_md5.items() if v['path'] in inputs}
    pubkeys_by_sha256 = {k: v for k, v in pubkeys_by_md5.items() if v['path'] in inputs}
    pubkeys_by_path = {k: v for k, v in pubkeys_by_md5.items() if k in inputs}

for key in agent_md5s:
    md5 = key['md5']
    if md5 in pubkeys_by_md5:
        pubkeys_by_md5[md5]['agent'] = True

for key in agent_sha256s:
    sha256 = key['sha256']
    if sha256 in pubkeys_by_sha256:
        pubkeys_by_sha256[sha256]['agent'] = True

if md5:
    agent_keys = agent_md5s
    all_keys = pubkeys_by_md5
    hsh = 'md5'
    other = sha256
else:
    agent_keys = agent_sha256s
    all_keys = pubkeys_by_sha256
    hsh = 'sha256'
    other = False


KEYS = [ 'md5', 'sha256', 'path', 'type', 'bits', 'comment' ]
if inputs or all:
    KEYS = [ lambda d: '*' if d['agent'] else ' ', ] + KEYS


def print_results(results):
    # print(results)
    for result in results:
        for key in KEYS:
            if callable(key):
                v = key(result)
                if v:
                    stdout.write(str(v) + field_separator)
            elif key in result:
                stdout.write(str(result[key]) + field_separator)
        stdout.write('\n')


if all or inputs:
    print_results(pubkeys)
else:
    agent_results = []
    for key in agent_keys:
        hash = key[hsh]
        if hash in all_keys:
            o = all_keys[hash]
            # o['agent'] = True
        else:
            o = {}
        result = merge(key, o)
        path = result.get('path', None)
        if path and other:
            result = merge(result, pubkeys_by_path[path])

        agent_results.append(result)

    print_results(agent_results)
