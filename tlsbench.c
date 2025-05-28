#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include <tls.h>

void
usage(void)
{
	fprintf(stderr, "tlsbench [-l] [address] [port]\n");
}

struct server {
	struct tls		*tls;
	struct tls_config	*config;
};

void
server(void)
{
	struct server srv;

	fprintf(stderr, "server\n");

	if ((server.tls = tls_server()) == NULL)
		err(1, "tls_server");

	if ((srv.config = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	if (tls_configure(tls, struct tls_config *config) == -1)
		err(1, "tls_configure");
}

int
client(void)
{
//	tls_config_insecure_noverifycert();
//	tls_config_insecure_noverifyname();
//	tls_config_insecure_noverifytime();

	return 0;
}

int
main(int argc, char *argv[])
{
	char	*addr = "0.0.0.0";
	char	*port = "12345";
	int	 lflag;
	int	 ch;

	while ((ch = getopt(argc, argv, "l")) != -1) {
		switch (ch) {
		case 'l':
			lflag = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0)
		addr = argv[0];
	if (argc > 1)
		port = argv[1];

	if (lflag)
		return server();

	return client();
}
