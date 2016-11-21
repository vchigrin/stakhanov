#!/usr/bin/env python
# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

import os
import subprocess

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DEST_FILE_NAME = os.path.join(SRC_DIR, 'build', 'LASTCHANGE')


def get_last_revision():
    args = ['git', 'log', '-1', '--format=%H']
    return subprocess.check_output(args, cwd=SRC_DIR)


def main():
    last_change = get_last_revision()
    with open(DEST_FILE_NAME, 'w') as f:
        f.write('LASTCHANGE=' + last_change)


if __name__ == '__main__':
    main()
