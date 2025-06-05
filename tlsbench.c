/*
 * Copyright (c) 2025 Jan Klemkow <j.klemkow@wemelug.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

struct server {
	struct tls		*tls;
	struct tls_config	*config;
	int			 fd;
};

static bool loop = true;
static bool dotls = true;

void
signal_handler(int sig)
{
	if (sig == SIGALRM)
		loop = false;
}

/* Get memory pointer of pkey or x509 object.*/
void
obj2data(uint8_t **data, size_t *size, EVP_PKEY *pkey, X509 *x509)
{
	BIO		*bio;
	BUF_MEM		 mem;

	memset(&mem, 0, sizeof mem);
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		errx(1, "BIO_new");
	if (BIO_set_mem_buf(bio, &mem, BIO_NOCLOSE) <= 0)
		errx(1, "BIO_set_mem_buf");

	if (x509 && PEM_write_bio_X509(bio, x509) == 0)
		err(1, "PEM_write_bio_X509");

	if (pkey && PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL,
	    NULL) == 0)
		errx(1, "PEM_write_bio_PrivateKey");

	if (BIO_free(bio) == 0)
		errx(1, "BIO_free");

	*data = mem.data;
	*size = mem.length;
}

/* Generate self sign certificate. */
void
sign(EVP_PKEY *pkey, uint8_t **crt, size_t *crt_size)
{
	X509		*x509;
	X509_NAME	*name;

	if ((x509 = X509_new()) == NULL)
		err(1, "X509_new");

	/* Set subject and issuer. */
	name = X509_get_subject_name(x509);
	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "localhost",
	    -1, -1, 0) == 0)
		err(1, "X509_NAME_add_entry_by_txt");
	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);

	/* Set serial number. */
	if (ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) == 0)
		err(1, "ASN1_INTEGER_set");
	/* Use certificate version 3. */
	if (X509_set_version(x509, 2) == 0)
		err(1, "X509_set_version");

	/* Expiration date: 30 days (60s * 60m * 24h * 30d) */
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 2592000);

	/* Sign the certificate with the key. */
	if (X509_set_pubkey(x509, pkey) == 0)
		err(1, "X509_set_pubkey");
	if (X509_sign(x509, pkey, EVP_sha256()) == 0)
		err(1, "X509_sign");

	obj2data(crt, crt_size, NULL, x509);

	X509_free(x509);
}

void
generate_rsa(uint8_t **key, size_t *key_size, uint8_t **crt, size_t *crt_size)
{
	EVP_PKEY	*pkey;
	EVP_PKEY_CTX	*ctx;

	/*
	 * Generate RSA key.
	 */
	if ((pkey = EVP_PKEY_new()) == NULL)
		err(1, "EVP_PKEY_new");
	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL)
		errx(1, "EVP_PKEY_CTX_new_id");
	if (EVP_PKEY_keygen_init(ctx) <= 0)
		errx(1, "EVP_PKEY_keygen_init");
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
		errx(1, "EVP_PKEY_CTX_set_rsa_keygen_bits");
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		errx(1, "EVP_PKEY_keygen");

	/* Get memory pointer of RSA key. */
	obj2data(key, key_size, pkey, NULL);

	sign(pkey, crt, crt_size);

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
}

void
generate_ec(uint8_t **key, size_t *key_size, uint8_t **crt, size_t *crt_size)
{
	EVP_PKEY	*pkey;
	EVP_PKEY_CTX	*ctx;
	char		 buf[BUFSIZ];

	/*
	 * Generate EC key.
	 */
	if ((pkey = EVP_PKEY_new()) == NULL)
		err(1, "EVP_PKEY_new");
	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
		errx(1, "EVP_PKEY_CTX_new_id");
	if (EVP_PKEY_keygen_init(ctx) <= 0)
		errx(1, "EVP_PKEY_keygen_init");
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
	    NID_X9_62_prime256v1) <= 0)
		errx(1, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid: %s",
		    ERR_error_string(ERR_get_error(), buf));
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		errx(1, "EVP_PKEY_keygen");

	/* Get memory pointer of EC key. */
	obj2data(key, key_size, pkey, NULL);

	sign(pkey, crt, crt_size);

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
}

int
server(struct sockaddr_in *sin, int jobs)
{
	struct server	 server;
	uint8_t		*crt = NULL;
	uint8_t		*key = NULL;
	size_t		 key_size;
	size_t		 crt_size;
	int		 c;

	memset(&server, 0, sizeof server);

	/*
	 * TLS preparation
	 */
	if (dotls) {
		if ((server.tls = tls_server()) == NULL)
			err(1, "tls_server");

		if ((server.config = tls_config_new()) == NULL)
			err(1, "tls_config_new");

		/* Generate key with selfsigned certificate. */
		generate_rsa(&key, &key_size, &crt, &crt_size);
		//generate_ec(&key, &key_size, &crt, &crt_size);
		if (tls_config_set_key_mem(server.config, key, key_size) == -1)
			errx(1, "%s", tls_config_error(server.config));
		if (tls_config_set_cert_mem(server.config, crt, crt_size) == -1)
			errx(1, "%s", tls_config_error(server.config));

		if (tls_configure(server.tls, server.config) == -1)
			err(1, "tls_configure");
	}

	/*
	 * Socket Handling
	 */
	if ((server.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	if (setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR,
	    (int []){1}, sizeof(int *)) == -1)
		err(1, "setsockopt");

	if (bind(server.fd, (struct sockaddr *)sin, sizeof *sin) == -1)
		err(1, "bind");

	if (listen(server.fd, 10) == -1)
		err(1, "listen");

	/* create jobs */
	for (int i = 0; i < jobs - 1; i++) {
		switch (fork()) {
		case -1:
			err(1, "fork");
		case 0: /* child */
			goto out;
		default: /* parent */
			continue;
		}
	}
 out:
	for (;;) {
		struct tls	*ctx;
		ssize_t		 ret;
		int		 data;

		if ((c = accept(server.fd, NULL, NULL)) == -1)
			err(1, "accept");

		if (dotls) {
			if (tls_accept_socket(server.tls, &ctx, c) == -1)
				err(1, "tls_accept_socket: %s",
				    tls_error(server.tls));

			if (tls_handshake(ctx) != 0)
				err(1, "tls_handshake: %s", tls_error(ctx));

			if ((ret = tls_close(ctx)) != 0)
				err(1, "tls_close: %s", tls_error(ctx));

			while ((ret = tls_read(ctx, &data, sizeof data)) != 0) {
				if (ret == -1)
					err(1, "tls_read: %s", tls_error(ctx));
				if (ret > 0)
					errx(1, "tls_read: unexpected data");
			}

			tls_free(ctx);
		}

		if (close(c) == -1)
			err(1, "close");
	}

	if (close(server.fd) == -1)
		err(1, "close");

	return 0;
}

int
client(struct sockaddr_in *sin)
{
	struct tls		*tls;
	struct tls_config	*config;
	ssize_t			 ret;
	int			 fd;
	int			 data;

	/*
	 * TLS preparation
	 */
	if (dotls) {
		if ((tls = tls_client()) == NULL)
			err(1, "tls_server");

		if ((config = tls_config_new()) == NULL)
			err(1, "tls_config_new");

		/* Don't check server certificate. */
		tls_config_insecure_noverifyname(config);
		tls_config_insecure_noverifycert(config);

		if (tls_configure(tls, config) == -1)
			err(1, "tls_configure");
	}

	/*
	 * Socket Handling
	 */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		if (errno == EINTR)
			return 0;
		err(1, "socket");
	}

	if (connect(fd, (struct sockaddr *)sin, sizeof *sin) == -1) {
		if (errno == EINTR)
			return 0;
		err(1, "connect");
	}

	if (dotls) {
		if (tls_connect_socket(tls, fd, "localhost") == -1)
			err(1, "tls_connect_socket: %s", tls_error(tls));

		if (tls_handshake(tls) != 0)
			errx(1, "tls_handshake: %s", tls_error(tls));

		if (tls_close(tls) != 0)
			err(1, "tls_close: %s", tls_error(tls));

		while ((ret = tls_read(tls, &data, sizeof data)) != 0) {
			if (ret == -1)
				err(1, "tls_read: %s", tls_error(tls));
			if (ret > 0)
				errx(1, "tls_read: unexpected data");
		}

		tls_free(tls);
		tls_config_free(config);
	} else {
		if (read(fd, &data, sizeof data) != 0) {
			if (errno == EINTR)
				return 0;
			err(1, "read");
		}
	}

	if (close(fd) == -1) {
		if (errno == EINTR)
			return 0;
		err(1, "close");
	}

	return 0;
}

void
usage(void)
{
	fprintf(stderr, "tlsbench [-Dl] [-j jobs] [-w sec] [address] [port]\n");
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in	 sin;
	const char		*errstr;
	char			*addr = "127.0.0.1";
	char			*port = "12345";
	size_t			 cnt = 0;
	unsigned int		 seconds = 5;
	int			 ch;
	int			 jobs = 1;
	int			 max_childs;
	bool			 lflag = false;

	if ((max_childs = sysconf(_SC_CHILD_MAX)) == -1)
		err(1, "sysconf(_SC_CHILD_MAX)");

	while ((ch = getopt(argc, argv, "Dj:lw:")) != -1) {
		switch (ch) {
		case 'D':
			dotls = false;
			break;

		case 'j':
			jobs = strtonum(optarg, 1, max_childs, &errstr);
			if (errstr != NULL)
				errx(1, "jobs: %s", errstr);
			break;

		case 'l':
			lflag = true;
			break;

		case 'w':
			seconds = strtonum(optarg, 1, UINT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "strtonum: %s", errstr);
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (lflag)
		addr = "0.0.0.0";

	if (argc > 0)
		addr = argv[0];
	if (argc > 1)
		port = argv[1];

	/*
	 * Set socket addess
 	 */
	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(strtonum(port, 1, USHRT_MAX, &errstr));
	if (errstr != NULL)
		errx(1, "invalid port number: %s: %s", errstr, port);

	switch (inet_pton(AF_INET, addr, &sin.sin_addr.s_addr)) {
	case -1:
		err(1, "inet_pton");
	case 0:
		errx(1, "invalid address: %s", addr);
	}

	if (lflag)
		return server(&sin, jobs);

	if (signal(SIGALRM, signal_handler) == SIG_ERR)
		err(1, "signal(SIGALRM)");

	int fd[jobs][2];

	for (int i = 0; i < jobs; i++) {
		if (pipe(fd[i]) == -1)
			err(1, "pipe");

		switch (fork()) {
		case -1:
			err(1, "fork");
		case 0: /* child */
			/* close the reading side */
			if (close(fd[i][0]) == -1)
				err(1, "close");

			/* set timer */
			if (alarm(seconds) == (unsigned int)-1)
				err(1, "alarm");

			/* count test runs */
			for (cnt = 0; loop; cnt++)
				client(&sin);

			/* write results to master */
			if (write(fd[i][1], &cnt, sizeof cnt) != sizeof cnt)
				err(1, "write");

			exit(EXIT_SUCCESS);
			break;
		default: /* parent */
			/* close the writing side */
			if (close(fd[i][1]) == -1)
				err(1, "close");
		}
	}

	/* collect the results */
	for (int i = 0; i < jobs; i++) {
		size_t c;

		if (read(fd[i][0], &c, sizeof c) != sizeof c)
			err(1, "read");
		cnt += c;
	}

	printf("%zu\n", cnt / seconds);

	return 0;
}
