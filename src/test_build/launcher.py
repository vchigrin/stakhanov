#!/usr/bin/env python
# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

import subprocess
import sys
import os


def main():
    new_env = {
        'NUMBER_OF_PROCESSORS': os.environ['NUMBER_OF_PROCESSORS'],
        'PROCESSOR_ARCHITECTURE': 'AMD64',
        'SystemRoot': r'C:\Windows',
        'Path': r'C:\Windows;C:\Windows\System32',
        'TMP': os.environ['TMP'],
    }
    process = subprocess.Popen(
        sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=new_env)
    output, err_output = process.communicate()
    process.wait()
    print '-' * 80
    print 'RETURN CODE {}'.format(process.returncode)
    print 'STDOUT:'
    print '-' * 80
    print output
    print '-' * 80
    print 'STDERR:'
    print '-' * 80
    print err_output
    print '-' * 80


if __name__ == '__main__':
    main()
