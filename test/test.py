#!/usr/bin/python3

import subprocess

import elftools.elf.elffile
import elftools.elf.segments

import pwn

ELF_FLAG_R = 1 << 2
ELF_FLAG_W = 1 << 1
ELF_FLAG_X = 1 << 0

# ./tracer 0x5555555551bf 0x5555555551d3 0x5555555551a1 > out

def get_sym_addr(elf, symname):
    try:
        symtab = elf.get_section_by_name('.symtab')
        sym = symtab.get_symbol_by_name(symname)[0]['st_value']
    except:
        return None

    return sym

def find_base_load_addr(elf):

    # Look for the first segment that is of type PT_LOAD
    # I am not sure if this is the correct way to look for
    # binary base load address, lol
    for segment in elf.iter_segments():
        if segment.header['p_type'] == 'PT_LOAD':
            return segment.header['p_offset']

    return None

def test1():
    # find addresses of add, sub and nop
    elf = elftools.elf.elffile.ELFFile(open('./tracee', 'rb'))

    base_addr = find_base_load_addr(elf)

    if base_addr == None:
        print('Failed to find binary base load address')
        exit(1)

    main_addr = get_sym_addr(elf, 'main')
    add_addr = get_sym_addr(elf, 'add')
    sub_addr = get_sym_addr(elf, 'sub')

    if main_addr == None or add_addr == None or sub_addr == None:
        print('Missing symbols!')
        exit(1)


    print(f'main @ {hex(base_addr + main_addr)}')


    # run ;]

if __name__ == '__main__':
    test1()
