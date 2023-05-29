#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <systemd/sd-daemon.h>
#include "utils.h"

int log_error_errno (int err, const char *fmt, ...)
{
	va_list ap;

	errno = err < 0 ? -err : err;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	return err;
}

int sigprocmask_many (int how, sigset_t *old, ...)
{
	int ret;
	va_list ap;
	sigset_t ss;

	ret = sigemptyset(&ss);
	if (ret < 0)
		return -errno;

	va_start(ap, old);

	for (;;) {
		int sig = va_arg(ap, int);
		if (sig < 0)
			break;

		ret = sigaddset(&ss, sig);
		if (ret < 0)
			goto out;
	}

	ret = sigprocmask(how, &ss, old);
out:
	va_end(ap);
	return ret < 0 ? -errno : 0;
}

int privdrop (const char *user)
{
	int ret;
	struct passwd *pw;

	if (getuid() != 0)
		return 0;

	pw = getpwnam(user);
	if (pw == NULL)
		return -ENOENT;

	ret = chroot(pw->pw_dir);
	if (ret < 0)
		return -errno;

	ret = chdir("/");
	if (ret < 0)
		return -errno;

	ret = setgroups(1, &pw->pw_gid);
	if (ret < 0)
		return -errno;

	ret = setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid);
	if (ret < 0)
		return -errno;

	ret = setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid);
	if (ret < 0)
		return -errno;

	return 0;
}

const char *notify_start (const char *start, const char *stop)
{
	if (start)
		(void) sd_notify(0, start);

	return stop;
}

void notify_on_cleanup (const char **p)
{
	if (*p)
		(void) sd_notify(0, *p);
}
