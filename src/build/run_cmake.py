#!/usr/bin/env python

import os
import subprocess

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CMAKE_DIR = os.path.join(SRC_DIR, 'third_party', 'cmake')
CMAKE_EXECUTABLE = os.path.join(CMAKE_DIR, 'bin', 'cmake.exe')
OUT_DIR = os.path.join(SRC_DIR, 'out')


def gen_for_build_type(build_type):
    dest_dir = os.path.join(OUT_DIR, build_type)
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    os.chdir(dest_dir)
    args = [
        CMAKE_EXECUTABLE,
        '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=' + build_type,
        SRC_DIR
    ]
    subprocess.check_call(args)


def main():
    gen_for_build_type('Debug')
    gen_for_build_type('Release')


if __name__ == '__main__':
    main()
