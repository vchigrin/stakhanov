// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STHOOK_INTERCEPTED_FUNCTIONS_H_
#define STHOOK_INTERCEPTED_FUNCTIONS_H_

#include <windows.h>

namespace sthook {

void Initialize(HMODULE current_module);

}  // namespace sthook

#endif  // STHOOK_INTERCEPTED_FUNCTIONS_H_

