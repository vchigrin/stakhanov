// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

int main(int argc, char* argv[]) {
  return reinterpret_cast<int>(&LoadLibraryW);
}
