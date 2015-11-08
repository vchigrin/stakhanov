#!/usr/bin/env python

"""Tool to download and extrace CMake for current platform.
"""

import os
import shutil
import sys
import urllib
import zipfile

# TODO(vchigrin): Various OS support.

DOWNLOAD_URL = 'https://cmake.org/files/v3.3/cmake-3.3.2-win32-x86.zip'
FILE_NAME = 'cmake-3.3.2-win32-x86.zip'

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
CACHE_DIR = os.path.join(SCRIPT_DIR, '.cache')
OUT_DIR = os.path.join(SCRIPT_DIR, '..', 'third_party', 'cmake')


def extract(archive):
    print "Extracting ", archive
    os.makedirs(OUT_DIR)
    try:
        zfile = zipfile.ZipFile(archive, 'r')
        for item in zfile.namelist():
            # Drop top-level dir - it is something like 'cmake-3.3.2-win32-x86'
            top_dir, path = item.split('/', 1)
            target_object = os.path.join(OUT_DIR, path)
            target_dir = os.path.dirname(target_object)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            with open(target_object, 'wb') as f:
                f.write(zfile.read(item))
    except:
        # Ensure next time we'll try download
        shutil.rmtree(OUT_DIR)
        raise


def download_and_extract():
    if os.path.exists(OUT_DIR):
        # already downloaded.
        return 0
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    archive = os.path.join(CACHE_DIR, FILE_NAME)
    if not os.path.exists(archive):
        print "Downloading ", DOWNLOAD_URL
        urllib.urlretrieve(DOWNLOAD_URL, archive)
        assert os.path.exists(archive)
    extract(archive)
    return 0


def main():
    return download_and_extract()


if __name__ == '__main__':
    sys.exit(main())
