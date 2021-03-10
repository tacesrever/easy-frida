

#include <sys/types.h>
#include <link.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>

#include <string>
#include <fstream>

#include "nlohmann/json.hpp"

#include "cathelper.h"

using namespace std;
using nlohmann::json;

void cat_log(const char* fmt, ...) {
	va_list args;
	char msg[1024];
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, args);
	va_end(args);
	if (debug_log) debug_log(msg);
	else adb_log("%s", msg);
}

size_t read_line(int fd, char* buf, size_t max_len) {
	char c;
	size_t readed, n = 0;

	memset(buf, 0, max_len);
	do {
		readed = read(fd, &c, 1);
		if (readed != 1) {
			if (n == 0) return -1;
			else return n;
		}

		if (c == '\n') return n;
		*(buf++) = c;
		n += 1;
	} while (n < max_len - 1);

	return n;
}

bool underZygote() {
	ifstream f_cmdline("/proc/self/cmdline");
	string cmdline;
	f_cmdline >> cmdline;
	f_cmdline.close();
#ifdef __aarch64__
	return strncmp(cmdline.c_str(), "zygote64", 8) == 0;
#else
	return strncmp(cmdline.c_str(), "zygote", 6) == 0;
#endif
}

bool is_target(const char* procname) {
	DIR* dir = opendir(FRIDA_SCRIPT_DIR);
	if (dir != NULL) {
		dirent* entry = NULL;
		while ((entry = readdir(dir)) != NULL) {
			if (entry->d_type != DT_DIR) {
				string fname = entry->d_name;
				if (fname.rfind(".config") + 7 == fname.length()) {
					json config;
					string fpath = FRIDA_SCRIPT_DIR;
					fpath = fpath.append(fname);
					ifstream conf_file(fpath);
					if (!conf_file.is_open()) continue;
					conf_file >> config;
					conf_file.close();
					json filter = config["filter"]["executables"];
					for (json& jname : filter) {
						string name = jname.get<string>();
						if (name.compare(procname) == 0) {
							return true;
						}
					}
				}
			}
		}
		closedir(dir);
	}
	return false;
}

void *mew(void* arg) {
	while (underZygote()) usleep(1000);
	uid_t uid = getuid();
	ifstream f_cmdline("/proc/self/cmdline");
	string cmdline;
	f_cmdline >> cmdline;
	f_cmdline.close();
	if (is_target(cmdline.c_str())) {
		cat_log("load frida-gadget for uid:%d, procname:%s", uid, cmdline.c_str());
		dlopen(LIB_FRIDA, RTLD_NOW);
	}
	return NULL;
}

void start_thread(int sign) {
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	// for v8 runtime to init without error, we need enough stacksize
	pthread_attr_setstacksize(&attr, 0xa00000);
	pthread_t tid;
	pthread_create(&tid, &attr, mew, NULL);
}

void atfork() {
	// wait for selinux_context switched.
	signal(SIGPROF, start_thread);
	struct itimerval time;
	time.it_interval.tv_sec = 0;
	time.it_interval.tv_usec = 0;
	time.it_value.tv_sec = 0;
	time.it_value.tv_usec = 60 * 1000;
	setitimer(ITIMER_PROF, &time, NULL);
}

INIT void set_atfork() {
	pthread_atfork(nullptr, nullptr, &atfork);
}