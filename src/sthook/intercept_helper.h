// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STHOOK_INTERCEPT_HELPER_H_
#define STHOOK_INTERCEPT_HELPER_H_

#include <windows.h>

#include "sthook/functions_interceptor.h"

namespace sthook {

class InterceptHelperBase {
 public:
  static void DisableAll() {
    is_enabled_ = false;
  }

  static bool is_enabled_;
};

struct InterceptHelperData {
  const char* function_name;
  void* before_call_ptr;
  void* after_call_ptr;
  void* original_function;
};

template<typename RESULT_TYPE, typename... ARGS>
class InterceptHelperTraits {
 public:
  typedef void (*BEFORE_CALL_PTR)(ARGS...);
  typedef void (*AFTER_CALL_PTR)(RESULT_TYPE result, ARGS...);
  typedef RESULT_TYPE (WINAPI *FUNCTION_PTR)(ARGS...);

  static RESULT_TYPE CallFunctionAndAfterCall(
      FUNCTION_PTR original_function,
      AFTER_CALL_PTR after_call,
      ARGS... args) {
    RESULT_TYPE result = original_function(args...);
    if (after_call)
      after_call(result, args...);
    return result;
  }
};

template<typename... ARGS>
class InterceptHelperTraits<void, ARGS...> {
 public:
  typedef void (*BEFORE_CALL_PTR)(ARGS...);
  typedef void (*AFTER_CALL_PTR)(ARGS...);
  typedef void (WINAPI *FUNCTION_PTR)(ARGS...);

  static void CallFunctionAndAfterCall(
      FUNCTION_PTR original_function,
      AFTER_CALL_PTR after_call,
      ARGS... args) {
    original_function(args...);
    if (after_call)
      after_call(args...);
  }
};

template<InterceptHelperData* intercept_data,
     typename RESULT_TYPE, typename... ARGS>
class InterceptHelper : public InterceptHelperBase {
 public:
  using Traits = InterceptHelperTraits<RESULT_TYPE, ARGS...>;

  static void Register(
      HMODULE module_handle,
      FunctionsInterceptor::DllInterceptedFunctions* intercepts_table) {
    intercept_data->original_function =
        GetProcAddress(module_handle, intercept_data->function_name);
    LOG4CPLUS_ASSERT(logger_, intercept_data->original_function);
    intercepts_table->insert(
        std::make_pair(intercept_data->function_name, &NewFunction));
    LOG4CPLUS_ASSERT(
        logger_,
        intercept_data->before_call_ptr != nullptr ||
            intercept_data->after_call_ptr != nullptr);
  }

 private:
  static RESULT_TYPE WINAPI NewFunction(ARGS... args) {
    auto original_function = reinterpret_cast<Traits::FUNCTION_PTR>(
        intercept_data->original_function);
    auto before_call = reinterpret_cast<Traits::BEFORE_CALL_PTR>(
        intercept_data->before_call_ptr);
    auto after_call = reinterpret_cast<Traits::AFTER_CALL_PTR>(
        intercept_data->after_call_ptr);
    if (!is_enabled_)
      return original_function(args...);
    if (before_call)
      before_call(args...);
    return Traits::CallFunctionAndAfterCall(
        original_function, after_call, args...);
  }
};

typedef void (*REGISTRATION_PTR)(
    HMODULE module_handle,
    FunctionsInterceptor::DllInterceptedFunctions* intercepts_table);

}  // namespace sthook
#endif  // STHOOK_INTERCEPT_HELPER_H_
