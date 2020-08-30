// Twin Guards
// MIT License Copyright (c) 2020 Hiroshi Shimamoto

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

static inline void ldatetime(char *dt, int sz)
{
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	if (!tmp)
		strcpy(dt, "-");
	else
		strftime(dt, sz, "%F %T", tmp);
}

#define logf(...) \
	do { \
		char dt[80]; \
		ldatetime(dt, sizeof(dt)); \
		fprintf(stderr, "%s [%d] ", dt, getpid()); \
		fprintf(stderr, __VA_ARGS__); \
		fflush(stderr); \
	} while (0)


struct target {
	char *cmdline;
	int found;
	pid_t pid;
};

char *guardfile;
char cmdline[256];

struct target targets[256];

int target_is_target(struct target *t, pid_t pid)
{
	char path[256];
	snprintf(path, 256, "/proc/%d/cmdline", pid);

	char buf[256];
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	int ret = read(fd, buf, 256);
	close(fd);

	if (ret <= 0)
		return -1;

	// logf("cmdline: %s\n", buf);

	for (int i = 0; i < strlen(t->cmdline); i++) {
		if (buf[i] == '\0' && t->cmdline[i] == ' ')
			continue;
		if (buf[i] != t->cmdline[i])
			return -1;
	}

	return 0;
}

void target_loockup(struct target *t)
{
	if (!t->cmdline)
		return;
	if (t->pid != 0)
		return;
	logf("lookup %s\n", t->cmdline);
	// walk /proc
	DIR *dp = opendir("/proc");
	struct dirent *dirst;
	while ((dirst = readdir(dp)) != NULL) {
		char ch = dirst->d_name[0];
		if (ch < '1' || '9' < ch)
			continue;
		//logf("/proc/%s\n", dirst->d_name);
		pid_t pid = atoi(dirst->d_name);
		if (target_is_target(t, pid) == -1)
			continue;
		logf("pid %d is %s\n", pid, t->cmdline);
		t->pid = atoi(dirst->d_name);
		break;
	}
	closedir(dp);
}

void target_invoke(struct target *t)
{
	logf("invoke: %s\n", t->cmdline);
	t->pid = 0; // forget once

	char buf[256];
	char *argv[256];

	strncpy(buf, t->cmdline, 256);

	int argc = 0;
	argv[argc] = buf;
	for (int i = 1; i < strlen(t->cmdline); i++) {
		if (buf[i] == ' ') {
			argc++;
			argv[argc] = &buf[i+1];
			buf[i] = 0;
		}
	}
	argc++;
	argv[argc] = NULL;

	pid_t pid = fork();
	if (pid < 0)
		return; // fork failed
	if (pid == 0) {
		// close all fds
		for (int i = 3; i < 256; i++)
			close(i);
		execvp(argv[0], argv);
		logf("execvp failed: %d\n", errno);
		_exit(1);
	}
	sleep(1);
	if (target_is_target(t, pid) == 0) {
		logf("running %d %s\n", pid, t->cmdline);
		t->pid = pid;
	}
}

struct target *get_target(char *cmdline)
{
	for (int i = 0; i < 256; i++) {
		struct target *t = &targets[i];
		if (!t->cmdline)
			continue;
		if (strcmp(t->cmdline, cmdline) == 0)
			return t;
	}
	return NULL;
}

void add_target(char *cmdline)
{
	for (int i = 0; i < 256; i++) {
		struct target *t = &targets[i];
		if (t->cmdline)
			continue;
		t->cmdline = strdup(cmdline);
		t->found = 1;
		logf("add target %s\n", cmdline);
		return;
	}
	logf("unable to add target\n");
}

void reinit_targets(void)
{
	for (int i = 0; i < 256; i++)
		targets[i].found = 0;
}

void refresh_targets(void)
{
	for (int i = 0; i < 256; i++) {
		struct target *t = &targets[i];
		if (t->cmdline && t->found == 0) {
			logf("no %s\n", t->cmdline);
			free(t->cmdline);
			t->cmdline = NULL;
		}
	}
}

void loadconfig(void)
{
	reinit_targets();

	FILE *fp = fopen(guardfile, "r");
	if (!fp)
		return;
	char buf[256];
	while (fgets(buf, 256, fp) != NULL) {
		char *lf = strchr(buf, '\n');
		if (lf == NULL)
			continue;
		*lf = 0;
		if (buf[0] == '#')
			continue;
		if (strlen(buf) == 0)
			continue;
		// check
		struct target *t = get_target(buf);
		if (t == NULL) {
			add_target(buf);
			continue;
		}
		t->found = 1;
	}
	fclose(fp);

	refresh_targets();
}

void check(void)
{
	logf("check targets\n");
	int n = 0;
	for (int i = 0; i < 256; i++) {
		struct target *t = &targets[i];

		if (n > 10)
			break;

		if (!t->cmdline)
			continue;

		target_loockup(t);
		if (t->pid == 0) {
			logf("unknown %s\n", t->cmdline);
			target_invoke(t);
			++n;
		}
		if (t->pid > 0) {
			if (target_is_target(t, t->pid) == -1) {
				logf("missing %d %s\n", t->pid, t->cmdline);
				target_invoke(t);
				++n;
				continue;
			}
			logf("alive %d %s\n", t->pid, t->cmdline);
		}
	}
}

void guard(pid_t pid, int rfd, int wfd, int ping)
{
	logf("guard with %d\n", pid);

	struct timeval tv, now;
	fd_set fds;
	int master = ping;

	gettimeofday(&now, NULL);
	for (;;) {
		if (ping) {
			if (master)
				check();
			logf("send ping\n");
			if (write(wfd, &ping, sizeof(ping)) < 0) {
				logf("ping error: %d\n", errno);
				break;
			}
			sleep(60);
			ping = 0;

			gettimeofday(&now, NULL);
		}

		FD_ZERO(&fds);
		FD_SET(rfd, &fds);
		tv.tv_sec = 60;
		tv.tv_usec = 0;
		int ret = select(rfd + 1, &fds, NULL, NULL, &tv);
		if (ret < 0) {
			logf("select error: %d\n", errno);
			break;
		}

		gettimeofday(&tv, NULL);
		if ((tv.tv_sec - now.tv_sec) > 120) {
			logf("timeout\n");
			break;
		}

		if (FD_ISSET(rfd, &fds)) {
			if (read(rfd, &ping, sizeof(ping)) <= 0) {
				logf("ping read error: close or %d\n", errno);
				break;
			}
			logf("get ping\n");

			// should be ping = 1
			ping = 1;
			sleep(1);
		}
	}
	// make a different sleep
	sleep(rfd % 10);
	// kill other
	logf("kill %d\n", pid);
	kill(pid, SIGKILL); // Force kill!
}

void twin(void)
{
	logf("start twin\n");
	loadconfig();

	int fds0[2], fds1[2];
	pipe(fds0);
	pipe(fds1);

	pid_t ret = fork();
	if (ret == -1) {
		logf("fork() failed %d\n", errno);
		goto out;
	}
	if (ret == 0) {
		// child side
		guard(getppid(), fds0[0], fds1[1], 0);
	} else {
		// parent
		guard(ret, fds1[0], fds0[1], 1);
	}

out:
	// cleanup
	close(fds0[0]); close(fds0[1]);
	close(fds1[0]); close(fds1[1]);

	logf("end twin\n");
	sleep(1); // interval
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "twinguards <guardfile>\n");
		return 1;
	}
	guardfile = argv[1];
	signal(SIGCHLD, SIG_IGN);
	for (;;)
		twin();
	return 0;
}
