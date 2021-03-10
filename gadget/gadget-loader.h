#pragma once

#include <android/log.h>
#define adb_log(...) __android_log_print(ANDROID_LOG_INFO, "frida-gadget-loader", __VA_ARGS__);

#define EXPORT __attribute__((visibility("default")))
#define INIT __attribute__((constructor))

#ifdef __aarch64__
#define LIB_FRIDA "/system/lib64/frida-gadget.so"
#else
#define LIB_FRIDA "/system/lib/frida-gadget.so"
#endif

#define FRIDA_SCRIPT_DIR "/data/local/tmp/frida_scripts/"

extern "C" {
	EXPORT void (*debug_log)(const char* msg);
}