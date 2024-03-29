#!/usr/bin/python3

import subprocess

from sys import stdout

import elftools.elf.elffile
import elftools.elf.segments

class termcolors:
    RED   = '\033[31m'
    GREEN = '\033[32m'
    GREY  = '\033[2;37m'
    WHITE = '\033[37m'
    RESET = '\033[0m'

def printcolored_(message: str, color: termcolors, end: str):
    stdout.write(color)
    stdout.write(message)
    stdout.write(end)
    stdout.write(termcolors.RESET)

def printcolored(message: str, color: termcolors):
    printcolored_(message, color, '')

def printlinecolored(message: str, color: termcolors):
    printcolored_(message, color, '\n')

import re

ELF_FLAG_R = 1 << 2
ELF_FLAG_W = 1 << 1
ELF_FLAG_X = 1 << 0

BINTRACE_PATH = '../bintrace'
TRACEE_PATH   = './tracee'

# ./tracer 0x5555555551bf 0x5555555551d3 0x5555555551a1 > out

class TestFailedException(Exception):
    pass

def get_sym_addr(elf, symname):
    try:
        symtab = elf.get_section_by_name('.symtab')
        sym = symtab.get_symbol_by_name(symname)[0]['st_value']
    except:
        return None

    return sym

def parse_proc_load_addr(stdout: str):
    p = re.compile('loaded at:(0x)?([0-9a-fA-F]+)')

    m = p.search(stdout)

    if not m:
        return None

    return int(m.groups()[-1], 16)

def test1():
    # find addresses of add, sub and nop
    elf = elftools.elf.elffile.ELFFile(open('./tracee', 'rb'))

    add_addr = get_sym_addr(elf, 'add')
    sub_addr = get_sym_addr(elf, 'sub')

    if add_addr == None or sub_addr == None:
        print('Missing symbols!')
        exit(1)

    test1_cmd = f'{BINTRACE_PATH} {TRACEE_PATH} {hex(add_addr)} {hex(sub_addr)}'
    stdout = subprocess.check_output(test1_cmd, shell=True).decode()

    load_addr = parse_proc_load_addr(stdout)

    if not load_addr:
        raise TestFailedException(f'Failed to obtain process load address from stdout:\n{stdout}')

    test1_expected_output = \
        "Trace history dump:\n" \
        f"{hex(load_addr + add_addr)}: 2\n" \
        f"{hex(load_addr + sub_addr)}: 1\n" \
        f"{hex(load_addr + add_addr)}: 1\n" \
        f"{hex(load_addr + sub_addr)}: 1\n"

    if stdout.find(test1_expected_output) == -1:
        fail_msg = "Unexpected output.\n" \
                   "Expected that output contains:\n" \
                   f"{test1_expected_output}\n" \
                   "\nGot:\n" \
                   f"{stdout}\n"

        raise TestFailedException(fail_msg)

def run_test(test):
    printlinecolored('#' * 60, termcolors.WHITE)
    print(f'Running test: {test.__name__}')
    printlinecolored('#' * 60, termcolors.WHITE)

    ex = None

    try:
        test()
    except TestFailedException as e:
        ex = e

    if ex:
        printlinecolored(f'{test.__name__} FAILED! Reason: {ex}', termcolors.RED)
    else:
        printlinecolored(f'{test.__name__} PASSED', termcolors.GREEN)

    printlinecolored('#' * 60 + '\n', termcolors.GREY)

if __name__ == '__main__':
    run_test(test1)

