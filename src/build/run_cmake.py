#!/usr/bin/env python
# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

import os
import subprocess

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CMAKE_DIR = os.path.join(SRC_DIR, 'third_party', 'cmake')
CMAKE_EXECUTABLE = os.path.join(CMAKE_DIR, 'bin', 'cmake.exe')
OUT_DIR = os.path.join(SRC_DIR, 'out')


def gen_for_build_type(build_type, folder_suffix):
    dest_dir = os.path.join(OUT_DIR, build_type + folder_suffix)
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


def grab_environ(bat_path, platform_type):
    args = [
        bat_path, platform_type, '&', 'set'
    ]
    output = subprocess.check_output(args)
    for line in output.split('\r'):
        line = line.strip()
        if not line:
            continue
        var_name, var_value = line.split('=', 1)
        os.environ[var_name] = var_value


def gen_for_platform(vs_dir, platform_type):
    bat_path = os.path.join(vs_dir, 'VC', 'vcvarsall.bat')
    grab_environ(bat_path, platform_type)
    gen_for_build_type('Debug', '_' + platform_type)
    gen_for_build_type('Release', '_' + platform_type)


def main():
    vs_dir = os.path.dirname(os.path.dirname(os.path.dirname(
        os.environ['VS140COMNTOOLS'])))
    gen_for_platform(vs_dir, 'x86')
    gen_for_platform(vs_dir, 'amd64')


if __name__ == '__main__':
    main()
