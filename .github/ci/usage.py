#!/usr/bin/env python3
"""usage.py [-1] ROOT HELP_JSON [OUT]: which commands and flags the fetched
trial and hunt results used.

ROOT holds one folder for each fetched run (fetch.sh puts a run in its DIR),
and trials/NAME for the trials. A source is one trial or one hunt round: a
command is counted once for a source however often it used it. With -1, ROOT
is one run and all of it is one source (fetch.sh does this for the run it
fetched). HELP_JSON is the output of `azhaq help -json` ("-" reads it from
stdin). It prints the commands by use and the flags no source used, native
apart from hidden, and writes OUT (default ROOT/usage.json).
"""
import collections
import json
import os
import re
import sys

TEXT = ('.log', '.md', '.txt', '.sh', '.jsonl')
# Files that quote azhaq's own commands, not what a run did.
SKIP_FILES = ('README.md', 'CHANGELOG.md', 'BRIEF.md', 'RULES.md')

INVOKE = re.compile(r'(?:^|[\s"\'`(;|&/])azhaq\s+([a-z]+)((?:\\\n|[^\n|;&`])*)')
FLAG = re.compile(r'(?:^|\s)-{1,2}([a-zA-Z][a-zA-Z0-9-]*)')


def source_of(root, dirpath, single):
    if single:
        return os.path.basename(os.path.abspath(root))
    rel = os.path.relpath(dirpath, root).split(os.sep)
    if rel[0] == 'trials':
        return '/'.join(rel[:2])
    return rel[0]


def read_text(path):
    try:
        with open(path, errors='replace') as f:
            text = f.read()
    except OSError:
        return ''
    if path.endswith('.jsonl'):
        text = text.replace('\\n', '\n').replace('\\"', '"')
    return text


def scan(root, flags_of, single):
    cmd_sources = collections.defaultdict(set)
    flag_sources = collections.defaultdict(set)
    calls = collections.Counter()
    sources = set()
    for dirpath, _, files in os.walk(root):
        if 'release-unpacked' in dirpath:
            continue
        src = source_of(root, dirpath, single)
        for name in files:
            if not name.endswith(TEXT) or name in SKIP_FILES or name.startswith('AREA-'):
                continue
            for m in INVOKE.finditer(read_text(os.path.join(dirpath, name))):
                cmd = m.group(1)
                if cmd not in flags_of:
                    continue
                sources.add(src)
                calls[cmd] += 1
                cmd_sources[cmd].add(src)
                for flag in FLAG.findall(m.group(2)):
                    if flag in flags_of[cmd]:
                        flag_sources[(cmd, flag)].add(src)
    return sources, cmd_sources, flag_sources, calls


def main(argv):
    args = argv[1:]
    single = bool(args) and args[0] == '-1'
    if single:
        args = args[1:]
    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    root, help_path = args[0], args[1]
    out = args[2] if len(args) > 2 else os.path.join(root, 'usage.json')
    try:
        help_ = json.load(sys.stdin if help_path == '-' else open(help_path))
    except (OSError, ValueError) as err:
        print(f'usage.py: cannot read {help_path}: {err}', file=sys.stderr)
        return 1
    # hidden: a flag azhaq keeps out of its help (absent before it said so).
    flags_of, hidden = {}, {}
    for c in help_['commands']:
        flags_of[c['name']] = {f['name'] for f in c.get('flags', [])}
        hidden[c['name']] = {f['name'] for f in c.get('flags', []) if f.get('hidden')}
    sources, cmd_sources, flag_sources, calls = scan(root, flags_of, single)

    print(f'sources: {len(sources)}')
    print('\n== commands by use: sources that used it, calls, flags used of all')
    for c in sorted(flags_of, key=lambda c: (-len(cmd_sources.get(c, ())), c)):
        used = sum(1 for f in flags_of[c] if (c, f) in flag_sources)
        print(f'{c:10} {len(cmd_sources.get(c, ())):4} sources {calls[c]:5} calls  flags {used:3}/{len(flags_of[c])}')

    never = {'native': {}, 'hidden': {}}
    for c in flags_of:
        for kind, names in (('native', flags_of[c] - hidden[c]), ('hidden', hidden[c])):
            left = sorted(f for f in names if (c, f) not in flag_sources)
            if left and c in cmd_sources:
                never[kind][c] = left
    for kind in ('native', 'hidden'):
        print(f'\n== flags never used, {kind} (commands some source used)')
        for c in sorted(never[kind], key=lambda c: (len(cmd_sources[c]), c)):
            print(f'{c}: ' + ' '.join('-' + f for f in never[kind][c]))

    result = {
        'sources': sorted(sources),
        'cmd': {c: sorted(v) for c, v in cmd_sources.items()},
        'calls': dict(calls),
        'flag': {f'{c} -{f}': sorted(v) for (c, f), v in flag_sources.items()},
        'never': never,
    }
    with open(out, 'w') as f:
        json.dump(result, f, indent=1, sort_keys=True)
    print(f'\nwrote {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
