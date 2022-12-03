/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_TRACEPOINT_H
#define __PERF_TRACEPOINT_H

#include <dirent.h>
#include <string.h>

int tp_event_has_id(const char *dir_path, struct dirent *evt_dir);

#define for_each_event(dir_path, evt_dir, evt_dirent)		\
	while ((evt_dirent = readdir(evt_dir)) != NULL/*读取evt_dir目录*/)		\
		if (evt_dirent->d_type == DT_DIR /*需要是目录*/&&		\
		    (strcmp(evt_dirent->d_name, "."))/*跳过'.','..'目录*/ &&	\
		    (strcmp(evt_dirent->d_name, "..")) &&	\
		    (!tp_event_has_id(dir_path, evt_dirent))/*必须存在id文件*/)

#define for_each_subsystem(sys_dir, sys_dirent)			\
	while ((sys_dirent = readdir(sys_dir)) != NULL)/*读取此目录*/	\
		if (sys_dirent->d_type == DT_DIR /*必须是目录*/&&		\
		    (strcmp(sys_dirent->d_name, ".")/*非.目录*/) &&	\
		    (strcmp(sys_dirent->d_name, "..")/*非..目录*/))

int is_valid_tracepoint(const char *event_string);

#endif /* __PERF_TRACEPOINT_H */
