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


def generate_build_bat(dest_dir, msvs_bat_file_command):
    lines = []
    # Save current dir and cd to build dir
    lines.append('pushd %~dp0')
    # Use local environment
    lines.append('setlocal')
    # Set up environment
    lines.append('call "{}" {}'.format(
        msvs_bat_file_command[0], ' '.join(msvs_bat_file_command[1:])))
    # Call ninja, passing it whatever user passed to .bat file.
    lines.append('ninja %*')
    # Restore environment
    lines.append('endlocal')
    # Restore directory
    lines.append('popd')
    dest_path = os.path.join(dest_dir, 'build.bat')
    with open(dest_path, 'w') as f:
        f.write('\n'.join(lines))


def gen_for_build_type(build_type, folder_suffix, msvs_bat_file_command):
    dest_dir = os.path.join(OUT_DIR, build_type + folder_suffix)
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    generate_build_bat(dest_dir, msvs_bat_file_command)
    os.chdir(dest_dir)
    args = [
        CMAKE_EXECUTABLE,
        '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=' + build_type,
        SRC_DIR
    ]
    subprocess.check_call(args)


def grab_environ(msvs_bat_file_command):
    args = list(msvs_bat_file_command)
    args.extend(['&', 'set'])
    output = subprocess.check_output(args)
    for line in output.split('\r'):
        line = line.strip()
        if not line:
            continue
        var_name, var_value = line.split('=', 1)
        os.environ[var_name] = var_value


def gen_for_platform(vs_dir, platform_type):
    bat_path = os.path.join(vs_dir, 'VC', 'vcvarsall.bat')
    msvs_bat_file_command = [bat_path, platform_type]
    grab_environ(msvs_bat_file_command)
    gen_for_build_type('Debug', '_' + platform_type, msvs_bat_file_command)
    gen_for_build_type('Release', '_' + platform_type, msvs_bat_file_command)


def main():
    vs_dir = os.path.dirname(os.path.dirname(os.path.dirname(
        os.environ['VS140COMNTOOLS'])))
    gen_for_platform(vs_dir, 'x86')
    gen_for_platform(vs_dir, 'amd64')


if __name__ == '__main__':
    main()
