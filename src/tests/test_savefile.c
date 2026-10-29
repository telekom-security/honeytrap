#define _GNU_SOURCE 1

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../attack.h"
#include "../conftree.h"
#include "../logging.h"
#include "../md5.h"
#include "../tcpip.h"

static int errors;

static void check_md5(const char *payload, const char *expected) {
	char *checksum = mem_md5sum((u_char *)payload, strlen(payload));

	assert(checksum != NULL);
	assert(strcmp(checksum, expected) == 0);
	free(checksum);
}

void logmsg(int level, int add_time, const char *format, ...) {
	va_list args;

	if (level > LOG_WARN) return;
	errors++;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

static void check_file(const char *path, const void *payload, size_t size) {
	struct stat info;
	unsigned char buffer[128];
	FILE *file;

	assert(size < sizeof(buffer));
	assert(stat(path, &info) == 0);
	assert((info.st_mode & 07777) == 0644);
	assert(info.st_uid == geteuid());
	assert(info.st_gid == getegid());
	assert(info.st_size == (off_t)size);
	file = fopen(path, "rb");
	assert(file != NULL);
	assert(fread(buffer, 1, sizeof(buffer), file) == size);
	assert(memcmp(buffer, payload, size) == 0);
	assert(fclose(file) == 0);
}

static void check_attack(const char *directory, unsigned int port,
	const void *payload, size_t size) {
	struct dirent *entry;
	DIR *dir = opendir(directory);
	char prefix[64], *path;
	int found = 0;

	assert(dir != NULL);
	snprintf(prefix, sizeof(prefix), "from_port_%u-tcp_", port);
	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0) continue;
		assert(asprintf(&path, "%s/%s", directory, entry->d_name) != -1);
		check_file(path, payload, size);
		free(path);
		found++;
	}
	assert(closedir(dir) == 0);
	assert(found == 1);
}

static void remove_directory(const char *directory) {
	DIR *dir = opendir(directory);
	struct dirent *entry;
	char *path;

	assert(dir != NULL);
	while ((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
		assert(asprintf(&path, "%s/%s", directory, entry->d_name) != -1);
		assert(unlink(path) == 0);
		free(path);
	}
	assert(closedir(dir) == 0);
	assert(rmdir(directory) == 0);
}

int main(void) {
	const char *tmp = getenv("TMPDIR");
	char *root, *attacks, *downloads, *blocked, *sample_path;
	const char **attacks_setting, **downloads_setting;
	void *module;
	int (*save)(Attack *);
	int previous_errors;
	unsigned char payload[] = "savefile attack\000binary";
	unsigned char sample[] = "inert sample\000binary";
	struct s_download download;
	Attack attack;

	check_md5("", "d41d8cd98f00b204e9800998ecf8427e");
	check_md5("abc", "900150983cd24fb0d6963f7d28e17f72");

	/* Permission failures must also be tested when make check is run as root. */
	if (geteuid() == 0) {
		assert(setgid(2000) == 0);
		assert(setuid(2000) == 0);
	}
	assert(geteuid() != 0);
	assert(asprintf(&root, "%s/honeytrap-savefile-XXXXXX", tmp ? tmp : "/tmp") != -1);
	assert(mkdtemp(root) != NULL);
	assert(asprintf(&attacks, "%s/attacks", root) != -1);
	assert(asprintf(&downloads, "%s/downloads", root) != -1);
	assert(asprintf(&blocked, "%s/blocked", root) != -1);
	assert(mkdir(attacks, 0700) == 0);
	assert(mkdir(downloads, 0700) == 0);
	assert(mkdir(blocked, 0500) == 0);

	module = dlopen("modules/.libs/htm_SaveFile.so", RTLD_LAZY);
	if (!module) {
		fprintf(stderr, "%s\n", dlerror());
		return EXIT_FAILURE;
	}
	save = dlsym(module, "save_to_file");
	attacks_setting = dlsym(module, "attacks_dir");
	downloads_setting = dlsym(module, "downloads_dir");
	assert(save != NULL && attacks_setting != NULL && downloads_setting != NULL);
	*attacks_setting = attacks;
	*downloads_setting = downloads;

	memset(&attack, 0, sizeof(attack));
	memset(&download, 0, sizeof(download));
	attack.a_conn.protocol = TCP;
	attack.a_conn.l_port = 2222;
	attack.a_conn.payload.data = payload;
	attack.a_conn.payload.size = sizeof(payload);
	download.filename = "sample.bin";
	download.dl_payload.data = sample;
	download.dl_payload.size = sizeof(sample);
	attack.download = &download;
	attack.dl_count = 1;
	umask(0077);
	assert(save(&attack) == 0);
	assert(errors == 0);
	check_attack(attacks, 2222, payload, sizeof(payload));
	assert(asprintf(&sample_path, "%s/%s-sample.bin", downloads,
		mem_md5sum(sample, sizeof(sample))) != -1);
	check_file(sample_path, sample, sizeof(sample));

	previous_errors = errors;
	attack.a_conn.payload.data = sample;
	attack.a_conn.payload.size = sizeof(sample);
	assert(save(&attack) == -1);
	assert(errors > previous_errors);
	check_attack(attacks, 2222, payload, sizeof(payload));
	check_file(sample_path, sample, sizeof(sample));
	attack.a_conn.payload.data = payload;
	attack.a_conn.payload.size = sizeof(payload);

	attack.a_conn.l_port++;
	previous_errors = errors;
	assert(save(&attack) == -1);
	assert(errors > previous_errors);
	check_file(sample_path, sample, sizeof(sample));
	free(sample_path);

	attack.a_conn.l_port++;
	download.filename = NULL;
	previous_errors = errors;
	assert(save(&attack) == 0);
	assert(errors == previous_errors);
	assert(asprintf(&sample_path, "%s/%s", downloads,
		mem_md5sum(sample, sizeof(sample))) != -1);
	check_file(sample_path, sample, sizeof(sample));
	free(sample_path);

	*attacks_setting = blocked;
	previous_errors = errors;
	assert(save(&attack) == -1);
	assert(errors > previous_errors);
	*attacks_setting = attacks;
	*downloads_setting = blocked;
	attack.a_conn.l_port++;
	previous_errors = errors;
	assert(save(&attack) == -1);
	assert(errors > previous_errors);
	assert(dlclose(module) == 0);

	remove_directory(attacks);
	remove_directory(downloads);
	assert(chmod(blocked, 0700) == 0);
	remove_directory(blocked);
	assert(rmdir(root) == 0);
	free(attacks);
	free(downloads);
	free(blocked);
	free(root);
	return EXIT_SUCCESS;
}
