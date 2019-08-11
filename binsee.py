#!/usr/bin/python3

from collections import Counter
import string

import asciiplotlib as apl
import numpy as np
import lief
import argparse

strings_of_interest = [
    'command',
    'debug',
    'http',
]

def f_red(t): return('\033[91m{}\033[00m'.format(t))
def f_green(t): return('\033[92m{}\033[00m'.format(t))
def f_yellow(t): return('\033[93m{}\033[00m'.format(t))


def print_header(t):
    print(f_yellow(t))
    print(f_yellow('-' * 50))


def entropy(b: bytearray()):
    c = Counter(b)
    lns = float(len(b))
    return -sum((count/lns * np.log(count/lns) for count in c.values())) / np.log(lns)


def binary_entropy(binary_file_path: str):
    h = []
    buffer_chunk_size = 256

    with open(binary_file_path, 'rb') as f:
        b = bytearray(f.read(buffer_chunk_size))
        while b:
            h.append(entropy(b))
            b = bytearray(f.read(buffer_chunk_size))

    return h, buffer_chunk_size


def plot_entropy(binary_file_path: str):
    entropy_per_buffer, buffer_chunk_size = binary_entropy(binary_file_path)

    average_entropy = sum(entropy_per_buffer) / len(entropy_per_buffer)
    if average_entropy >= 0.8:
        average_entropy = f_red(average_entropy)
    else:
        average_entropy = f_green(average_entropy)
    print('Average entropy: {}'.format(average_entropy))

    fig = apl.figure()
    x = np.linspace(0, len(entropy_per_buffer) * buffer_chunk_size, len(entropy_per_buffer))
    fig.plot(x, entropy_per_buffer, label="Entropy(E)", width=200, height=30)
    fig.show()


def parse_bin(binary_file_path):
    b = lief.parse(binary_file_path)
    return b.header, [x.name for x in b.imported_functions]


def strings(binary_file_path):
    sl = []
    with open(binary_file_path, errors='ignore') as f:
        s = ''
        for c in f.read():
            if c in string.printable:
                s += c
            else:
                if len(s) >= 4:
                    sl.append(s)
                s = ''
    return sl


def print_interesting_strings(binary_file_path: str):
    for s1 in strings(binary_file_path):
        if len(s1.split(' ')) > 3:
            print(s1, end=', ')
            continue
        for s2 in strings_of_interest:
            if s2 in s1.lower():
                print(f_red(s1), end=', ')
                continue


def parse_args():
    parser = argparse.ArgumentParser(description='Show binary')
    parser.add_argument('binary_file', type=str, help='Path to binary file')
    return parser.parse_args()


def main():

    args = parse_args()
    binary_file_path = args.binary_file

    header, impfun = parse_bin(binary_file_path)

    print_header('Header')
    print(header)
    print('\n')

    print_header('Entropy')
    plot_entropy(binary_file_path)
    print('\n')

    print_header('Imported functions')
    print(impfun)
    print('\n')

    print_header('Strings of interest')
    print_interesting_strings(binary_file_path)

if __name__ == '__main__':
    main()
