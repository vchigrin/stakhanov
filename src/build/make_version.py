#!/usr/bin/env python
# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

import os
import re
import sys

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BUILD_DIR = os.path.join(SRC_DIR, 'build')


def main():
    input_file_paths = [
        os.path.join(BUILD_DIR, 'LASTCHANGE'),
        os.path.join(BUILD_DIR, 'VERSION')
    ]
    output_file_name = sys.argv[1]
    input_file_paths.extend(sys.argv[2:])
    variables_dict = {}
    for file_path in input_file_paths:
        with open(file_path) as f:
            for line in f:
                key, value = line.strip().split('=', 1)
                variables_dict[key] = value
    template_path = os.path.join(BUILD_DIR, 'version.tmpl')
    output_lines = []
    with open(template_path) as f:
        re_var = re.compile('@(?P<var_name>[^@]+)@')
        for line in f:
            line = line.strip()
            cur_pos = 0
            output_line_parts = []
            while True:
                match = re_var.search(line, cur_pos)
                if match is None:
                    output_line_parts.append(line[cur_pos:])
                    break
                output_line_parts.append(line[cur_pos:match.start()])
                var_name = match.group('var_name')
                output_line_parts.append(variables_dict[var_name])
                cur_pos = match.end()
            output_lines.append(''.join(output_line_parts))
    with open(output_file_name, 'w') as f:
        f.write('\n'.join(output_lines))


if __name__ == '__main__':
    main()
