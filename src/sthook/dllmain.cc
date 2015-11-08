#include <windows.h>

void InstallHooks() {
}

BOOL CALLBACK DllMain(HINSTANCE h_instance, DWORD reason) {
  if (reason == DLL_PROCESS_ATTACH)
    InstallHooks();
  return TRUE;
}
