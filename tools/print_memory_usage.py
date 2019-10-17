#!/usr/bin/env python3
#
# Prints out the memory usage of a Tock kernel binary ELF.
#
# Usage: print_memory_usage.py ELF
#
# Author: Philip Levis <philip.levis@gmail.com>

# pylint: disable=superfluous-parens
'''
Script to print out the memory usage of a Tock kernel binary ELF.

Usage: print_memory_usage.py ELF
Options:
  -dn, --depth=n      Group symbols at depth n or greater. E.g.,
                      depth=2 will group all h1b::uart:: symbols
                      together. Default: 1
  -v, --verbose       Print verbose output.
  -s, --show-waste    Show where RAM is wasted (due to padding)
'''

import os
import re
import sys
import getopt
import cxxfilt   # Demanging C++/Rust symbol names


verbose = False
show_waste = False
symbol_depth = 1

# A map of section name -> size
sections = {}

# These lists store 4-tuples:
#    (name, start address, length of function, total size)
# The "length of function" is the size of the symbol as reported in
# objdump, which is the executable code. "Total size" includes any
# constants embedded, including constant strings, or padding.
# Initially the lists are populated with total_size=0; it is later
# computed by sorting the symbols and calculating their spacing.
kernel_uninitialized = []
kernel_initialized = []
kernel_functions = []

def usage(message):
    if message:
        print("  error: " + message)
        print("  usage: " + sys.argv[0] + " ELF")

# Read a line from the Sections: header and insert it into
 # the map of sections.
def process_section_line(line):
    # pylint: disable=anomalous-backslash-in-string,line-too-long
    match = re.search('^\S+\s+\.(text|relocate|sram|stack|app_memory)\s+(\S+).+', line)
    if match != None:
        sections[match.group(1)] = int(match.group(2), 16)

 # Take a Rust-style symbol of '::' delineated names and trim the last
 # one if it is a hash.  Many symbols have hashes appended which just
 # hurt readability; they take the form of h[16-digit hex number].
def trim_hash_from_symbol(symbol):
    # Remove the hash off the end
    tokens = symbol.split('::')
    last = tokens[-1]
    if last[0] == 'h':
        tokens = tokens[:-1] # Trim off hash if it exists
        trimmed_name = "::".join(tokens) # reassemble
        return trimmed_name
    else:
        return symbol

 # Take a potentially mangled symbol name and demangle it to its
 # name, removing the trailing hash. Raise a cxxflit.InvalidName exception
 # if it is not a mangled symbol.
def parse_mangled_name(name):
    demangled = cxxfilt.demangle(name, external_only=False)
    corrected_name = trim_hash_from_symbol(demangled)
    return corrected_name

 # Parse a line the SYMBOL TABLE section of the objdump output and
 # insert its data into one of the three kernel_ symbol lists.
 # Because Tock executables have a variety of symbol formats,
 # first try to demangle it; if that fails, use it as is.
def process_symbol_line(line):
    # pylint: disable=line-too-long,anomalous-backslash-in-string
    match = re.search('^(\S+)\s+\w+\s+\w*\s+\.(text|relocate|sram|stack|app_memory)\s+(\S+)\s+(.+)', line)
    if match != None:
        addr = int(match.group(1), 16)
        segment = match.group(2)
        size = int(match.group(3), 16)
        name = match.group(4)

        # Initialized data: part of the flash image, then copied into RAM
        # on start. The .data section in normal hosted C.
        if segment == "relocate":
            try:
                demangled = parse_mangled_name(name)
                kernel_initialized.append((demangled, addr, size, 0))
            except cxxfilt.InvalidName as e:
                kernel_initialized.append((name, addr, size, 0))

        # Uninitialized data, stored in a zeroed RAM section. The
        # .bss section in normal hosted C.
        elif segment == "sram":
            try:
                demangled = parse_mangled_name(name)
                kernel_uninitialized.append((demangled, addr, size, 0))
            except cxxfilt.InvalidName as e:
                kernel_uninitialized.append((name, addr, size, 0))

        # Code and embedded data.
        elif segment == "text":
            # pylint: disable=anomalous-backslash-in-string
            match = re.search('\$(((\w+\.\.)+)(\w+))\$', name)
            if match != None:
                symbol = match.group(1)
                symbol = symbol.replace('..', '::')
                symbol = trim_hash_from_symbol(symbol)
                kernel_functions.append((symbol, addr, size, 0))
            else:
                try:
                    symbol = parse_mangled_name(name)
                    kernel_functions.append((symbol, addr, size, 0))
                except cxxfilt.InvalidName as e:
                    kernel_functions.append((name, addr, size, 0))

def print_section_information():
    text_size = sections["text"]
    stack_size = sections["stack"]
    relocate_size = sections["relocate"]
    sram_size = sections["sram"]
    app_size = sections["app_memory"]

    flash_size = text_size + relocate_size
    ram_size = stack_size + sram_size + relocate_size

    print("Kernel occupies " + str(flash_size) + " bytes of flash")
    print("  " + "{:>6}".format(text_size) + "\tcode and constant strings")
    print("  " + "{:>6}".format(relocate_size) + "\tvariable initializers")
    print("Kernel occupies " + str(ram_size) + " bytes of RAM")
    print("  " + "{:>6}".format(stack_size) + "\tstack")
    print("  " + "{:>6}".format(sram_size) + "\tuninitialized variables")
    print("  " + "{:>6}".format(relocate_size) + "\tinitialized variables")
    print("  " + "{:>6}".format(sram_size + relocate_size) + "\tvariables total")
    print("Applications allocated " + str(app_size) + " bytes of RAM")

    # Take a list of 'symbols' and group them into in 'groups' as aggregates
    # for condensing. Names are '::' delimited hierarchies. xThe aggregate
    # sizes are determined by the global symbol depth, which indicates how
    # many levels of the naming heirarchy to display. A depth of 0 means
    # group all symbols together into one category; a depth of 1 means
    # aggregate symbols into top level categories (e.g, 'h1b::*'). A depth
    # of 100 means aggregate symbols only if they have the same first 100
    # name levels, so effectively print every symbol individually.
    #
    # The 'waste' and 'section' parameters are used to specify whether detected
    # waste should be printed and the name of the section for waste information.
def group_symbols(groups, symbols, waste, section):
    global symbol_depth
    expected_addr = 0
    waste_sum = 0
    prev_symbol = ""
    for (symbol, addr, size, total_size) in symbols:
        if size == 0:
            continue
        # If we find a gap between symbol+size and the next symbol, we might
        # have waste. But this is only true if it's not the first symbol and
        # this is actually a variable and just just a symbol (e.g., _estart)
        if addr != expected_addr and expected_addr != 0 and size != 0 and (waste or verbose):
            print("  ! " + str(addr - expected_addr) + " bytes wasted after " + prev_symbol)
        waste_sum = waste_sum + (addr - expected_addr)
        tokens = symbol.split("::")
        key = symbol[0] # Default to first character (_) if not a proper symbol
        name = symbol

        if len(tokens) == 1:
            # The symbol isn't a standard mangled Rust name. These rules are
            # based on observation.
            # .Lanon* and str.* are embedded string.
            if symbol[0:6] == '.Lanon' or symbol[0:5] == "anon." or symbol[0:4] == 'str.':
                key = "Constant strings"
            elif symbol[0:8] == ".hidden ":
                key = "ARM aeabi support"
            elif symbol[0:3] == "_ZN":
                key = "Unidentified auto-generated"
            else:
                key = "Unmangled globals (C-like code)"
                name = symbol
        else:
            # Packages have a trailing :: while other categories don't;
            # this allows us to disambiguate when * is relevant or not
            # in printing.
            key = "::".join(tokens[0:symbol_depth]) + "::"
            name = "::".join(tokens[symbol_depth:])

            if key in groups.keys():
                groups[key].append((name, size))
            else:
                groups[key] = [(name, size)]

        # Set state for next iteration
        expected_addr = addr + size
        prev_symbol = symbol

    if waste and waste_sum > 0:
        print("Total of " + str(waste_sum) + " bytes wasted in " + section)
        print()

 # Return the string for a group of variables, with padding added on the
 # right; decides whether to add a * or not based on the name of the group
 # and number of elements in it.
def string_for_group(key, padding_size, group_size, num_elements):
    if num_elements == 1: # If there's a single symbol (a variable), print it.
        key = key[:-2]
        key = key + ":"
        key = key.ljust(padding_size + 2, ' ')
        return ("  " + key + str(group_size) + " bytes\n")
    else: # If there's more than one, print the key as a namespace
        if key[-2:] == "::":
            key = key + "*"
            key = key.ljust(padding_size + 2, ' ')
            return ("  " + key + str(group_size) + " bytes\n")
        else:
            key = key + ":"
            key = key.ljust(padding_size + 2, ' ')
            return ("  " + key + str(group_size) + " bytes\n")

 # Print all of the variable groups under a title.
def print_groups(title, groups):
    group_sum = 0
    output = ""
    max_string_len = len(max(groups.keys(), key=len))
    for key in sorted(groups.keys()):
        symbols = groups[key]

        group_size = 0
        for (_, size) in symbols:
            group_size = group_size + size

        output = output + string_for_group(key, max_string_len, group_size, len(symbols))
        group_sum = group_sum + group_size

    print(title + ": " + str(group_sum) + " bytes")
    print(output, end=' ')

 # Print information on symbols (variables and functions)
def print_symbol_information():
    variable_groups = {}
    group_symbols(variable_groups, kernel_initialized, show_waste, "RAM")
    group_symbols(variable_groups, kernel_uninitialized, show_waste, "Flash+RAM")
    print_groups("Variable groups (RAM)", variable_groups)

    print()
    print("Embedded data (in flash): " + str(padding_text) + " bytes")
    print()
    function_groups = {}
    # Embedded constants in code (e.g., after functions) aren't counted
    # in the symbol's size, so detecting waste in code has too many false
    # positives.
    group_symbols(function_groups, kernel_functions, False, "Flash")
    print_groups("Function groups (in flash)", function_groups)
    print()

def compute_padding(symbols):
    func_count = len(symbols)
    diff = 0
    for i in range(1, func_count):
        (esymbol, eaddr, esize, _) = symbols[i - 1]
        (_, laddr, _, _) = symbols[i]
        total_size = laddr - eaddr
        symbols[i - 1] = (esymbol, eaddr, esize, total_size)
        if total_size != esize:
            diff = diff + (total_size - esize)

    return diff

def get_addr(symbol_entry):
    return symbol_entry[1]

def parse_options(opts):
    global symbol_depth, verbose, show_waste
    valid = 'd:vs'
    long_valid = ['depth=', 'verbose', 'show-waste']
    optlist, _ = getopt.getopt(opts, valid, long_valid)
    for (opt, val) in optlist:
        if opt == '-d' or opt == '--depth':
            symbol_depth = int(val)
        if opt == '-v' or opt == '--verbose':
            verbose = True
        if opt == '-s' or opt == '--show-waste':
            show_waste = True

 # Script starts here ######################################
arguments = sys.argv[1:]
if len(arguments) < 1:
    usage("no ELF specified")
    sys.exit(-1)

 # The ELF is always the last argument; pull it out, then parse
 # the others.
elf_name = arguments[-1]
options = arguments[:-1]
parse_options(options)

header_lines = os.popen('arm-none-eabi-objdump -f ' + elf_name).readlines()

print("Tock memory usage report for " + elf_name)
arch = "UNKNOWN"

for hline in header_lines:
    # pylint: disable:anomalous-backslash-in-string
    hmatch = re.search('file format (\S+)', hline)
    if hmatch != None:
        arch = hmatch.group(1)
        if arch != 'elf32-littlearm':
            usage(arch + " architecture not supported, only elf32-littlearm supportd")
            sys.exit(-1)

if arch == "UNKNOWN":
    usage("could not detect architecture of ELF")
    sys.exit(-1)

objdump_lines = os.popen('arm-none-eabi-objdump -x ' + elf_name).readlines()
objdump_output_section = "start"

for line in objdump_lines:
    line = line.strip()
    # First, move to a new section if we've reached it; use continue
    # to break out and reduce nesting.
    if line == "Sections:":
        objdump_output_section = "sections"
        continue
    elif line == "SYMBOL TABLE:":
        objdump_output_section = "symbol_table"
        continue
    elif objdump_output_section == "sections":
        process_section_line(line)
    elif objdump_output_section == "symbol_table":
        process_symbol_line(line)

kernel_initialized.sort(key=get_addr)
kernel_uninitialized.sort(key=get_addr)
kernel_functions.sort(key=get_addr)

padding_init = compute_padding(kernel_initialized)
padding_uninit = compute_padding(kernel_uninitialized)
padding_text = compute_padding(kernel_functions)

print_section_information()
print()
print_symbol_information()