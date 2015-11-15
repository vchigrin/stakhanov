#!/usr/bin/env python
# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

"""Tool to download and extract third_party dependency.
"""

import argparse
import os
import shutil
import sys
import urllib
import zipfile

# TODO(vchigrin): Various OS support.

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
CACHE_DIR = os.path.join(SCRIPT_DIR, '.cache')
THIRD_PARTY_DIR = os.path.join(SCRIPT_DIR, '..', 'third_party')


def has_same_top_dir(name_list):
    known_top_dir = None
    for name in name_list:
        top_dir, path = name.split('/', 1)
        if known_top_dir is None:
            known_top_dir = top_dir
        elif known_top_dir != top_dir:
            return False
    return True


def extract(archive, out_dir):
    print "Extracting ", archive
    os.makedirs(out_dir)
    try:
        zfile = zipfile.ZipFile(archive, 'r')
        strip_top_dir = has_same_top_dir(zfile.namelist())
        for item in zfile.namelist():
            if strip_top_dir:
                # Drop top-level dir
                path = item.split('/', 1)[1]
            else:
                path = item
            target_object = os.path.join(out_dir, path)
            target_dir = os.path.dirname(target_object)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            if target_object[-1] == '/':
                continue
            with open(target_object, 'wb') as f:
                f.write(zfile.read(item))
    except:
        # Ensure next time we'll try download
        shutil.rmtree(out_dir)
        raise


def download_and_extract(url, file_name, dir_name):
    out_dir = os.path.join(THIRD_PARTY_DIR, dir_name)
    if os.path.exists(out_dir):
        # already downloaded.
        return 0
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    archive = os.path.join(CACHE_DIR, file_name)
    if not os.path.exists(archive):
        print "Downloading ", url
        urllib.urlretrieve(url, archive)
        assert os.path.exists(archive)
    extract(archive, out_dir)
    return 0


def main(argv):
    parser = argparse.ArgumentParser(
        description='Download and unzip third-party dependency')
    parser.add_argument('url')
    parser.add_argument('file_name')
    parser.add_argument('dir_name')
    args = parser.parse_args()
    return download_and_extract(args.url, args.file_name, args.dir_name)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
