// SPDX-License-Identifier: GPL-2.0
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/string.h>
#include <errno.h>
#include <unistd.h>
#include "fs.h"

#include "tracing_path.h"

static char tracing_path[PATH_MAX]        = "/sys/kernel/tracing";

/*设置这些全局变量*/
static void __tracing_path_set(const char *tracing, const char *mountpoint)
{
	snprintf(tracing_path, sizeof(tracing_path), "%s/%s",
		 mountpoint, tracing);
}


/*取tracefs挂载的目录*/
static const char *tracing_path_tracefs_mount(void)
{
	const char *mnt;

	/*挂载tracefs*/
	mnt = tracefs__mount();
	if (!mnt)
		return NULL;

	__tracing_path_set("", mnt);

	return tracing_path;
}

static const char *tracing_path_debugfs_mount(void)
{
	const char *mnt;

	/*挂载debugfs*/
	mnt = debugfs__mount();
	if (!mnt)
		return NULL;

	__tracing_path_set("tracing/", mnt);

	return tracing_path;
}

const char *tracing_path_mount(void)
{
	const char *mnt;

	/*返回tracefs挂载点*/
	mnt = tracing_path_tracefs_mount();
	if (mnt)
		return mnt;

	/*返回debugfs挂载点*/
	mnt = tracing_path_debugfs_mount();

	return mnt;
}

void tracing_path_set(const char *mntpt)
{
	__tracing_path_set("tracing/", mntpt);
}

/*返回trace文件的路径,例如/sys/kernel/debug/tracing/$name */
char *get_tracing_file(const char *name)
{
	char *file;

	if (asprintf(&file, "%s/%s", tracing_path_mount(), name) < 0)
		return NULL;

	return file;
}

void put_tracing_file(char *file)
{
	free(file);
}

char *get_events_file(const char *name)
{
	char *file;

	if (asprintf(&file, "%s/events/%s", tracing_path_mount(), name) < 0)
		return NULL;

	return file;
}

void put_events_file(char *file)
{
	free(file);
}

/*打开并返回events目录*/
DIR *tracing_events__opendir(void)
{
	DIR *dir = NULL;
	char *path = get_tracing_file("events");

	if (path) {
	    /*打开events目录*/
		dir = opendir(path);
		put_events_file(path);
	}

	return dir;
}

int tracing_events__scandir_alphasort(struct dirent ***namelist)
{
	/*打开并返回events目录*/
	char *path = get_tracing_file("events");
	int ret;

	if (!path) {
		*namelist = NULL;
		return 0;
	}

	ret = scandir(path, namelist, NULL, alphasort);
	put_events_file(path);

	return ret;
}

int tracing_path__strerror_open_tp(int err, char *buf, size_t size,
				   const char *sys, const char *name)
{
	char sbuf[128];
	char filename[PATH_MAX];

	snprintf(filename, PATH_MAX, "%s/%s", sys, name ?: "*");

	switch (err) {
	case ENOENT:
		/*
		 * We will get here if we can't find the tracepoint, but one of
		 * debugfs or tracefs is configured, which means you probably
		 * want some tracepoint which wasn't compiled in your kernel.
		 * - jirka
		 */
		if (debugfs__configured() || tracefs__configured()) {
			/* sdt markers */
			if (!strncmp(filename, "sdt_", 4)) {
				snprintf(buf, size,
					"Error:\tFile %s/events/%s not found.\n"
					"Hint:\tSDT event cannot be directly recorded on.\n"
					"\tPlease first use 'perf probe %s:%s' before recording it.\n",
					tracing_path, filename, sys, name);
			} else {
				snprintf(buf, size,
					 "Error:\tFile %s/events/%s not found.\n"
					 "Hint:\tPerhaps this kernel misses some CONFIG_ setting to enable this feature?.\n",
					 tracing_path, filename);
			}
			break;
		}
		snprintf(buf, size, "%s",
			 "Error:\tUnable to find debugfs/tracefs\n"
			 "Hint:\tWas your kernel compiled with debugfs/tracefs support?\n"
			 "Hint:\tIs the debugfs/tracefs filesystem mounted?\n"
			 "Hint:\tTry 'sudo mount -t debugfs nodev /sys/kernel/debug'");
		break;
	case EACCES: {
		snprintf(buf, size,
			 "Error:\tNo permissions to read %s/events/%s\n"
			 "Hint:\tTry 'sudo mount -o remount,mode=755 %s'\n",
			 tracing_path, filename, tracing_path_mount());
	}
		break;
	default:
		snprintf(buf, size, "%s", str_error_r(err, sbuf, sizeof(sbuf)));
		break;
	}

	return 0;
}
