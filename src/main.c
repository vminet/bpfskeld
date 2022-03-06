#include <stdio.h>
#include <getopt.h>
#include <libgen.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include "utils.h"
#include "manager.h"

static int debug = 0;
static const char *user = "nobody";

static void usage (const char *argv0)
{
	fprintf(stderr, "usage: %s [options]\n", basename((char *)argv0));
	fprintf(stderr,
	        "  -h, --help          show this usage and exit\n"
	        "  -V, --version       show version and exit\n"
	        "  -d, --debug         print debug message\n"
	        "  -u, --user <name>   run as user <name>\n");
}

static void parse_option (int argc, char *argv[])
{
	int c;
	static const struct option options[] = {
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ "debug",   no_argument,       NULL, 'd' },
		{ "user",    required_argument, NULL, 'u' },
		{ NULL },
	};

	for (;;) {
		c = getopt_long(argc, argv, "hVdu:", options, NULL);
		if (c < 0)
			break;

		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);

		case 'V':
			printf("bpfskeld " stringify(PROJECT_VERSION) "\n");
			exit(EXIT_SUCCESS);

		case 'd':
			debug = 1;
			break;

		case 'u':
			user = optarg;
			break;

		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}

static int libbpf_print (enum libbpf_print_level level, const char *format, va_list args)
{
	if (!debug && level == LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

int main (int argc, char *argv[])
{
	int ret;
	__cleanup(manager_freep) struct manager *m = NULL;
	__cleanup(notify_on_cleanup) const char *notify_stop = NULL;

	parse_option(argc, argv);

	ret = sigprocmask_many(SIG_BLOCK, NULL, SIGINT, SIGTERM, -1);
	if (ret < 0)
		return log_error_errno(ret, "failed to block signal: %m\n");

	ret = bump_memlock_rlimit();
	if (ret < 0)
		return log_error_errno(ret, "failed to bump memory limit: %m\n");

	libbpf_set_print(libbpf_print);

	ret = manager_new(&m);
	if (ret < 0)
		return log_error_errno(ret, "failed to create manager: %m\n");

	if (geteuid() == 0) {
		ret = privdrop(user);
		if (ret < 0)
			return log_error_errno(ret, "failed to drop privileges: %m\n");
	}

	notify_stop = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

	ret = sd_event_loop(m->event);
	if (ret < 0)
		return log_error_errno(ret, "event loop failed: %m\n");

	return 0;
}
