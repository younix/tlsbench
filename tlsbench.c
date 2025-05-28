#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

struct server {
	struct tls		*tls;
	struct tls_config	*config;
	int			 fd;
};

void
generate_cert(uint8_t **key, size_t *key_size, uint8_t **crt, size_t *crt_size)
{
	EVP_PKEY	*pkey;
	EVP_PKEY_CTX	*ctx;
	X509		*x509;
	X509_NAME	*name;
	BIO		*bio;
	BUF_MEM		 mem;

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
	memset(&mem, 0, sizeof mem);
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		errx(1, "BIO_new");
	if (BIO_set_mem_buf(bio, &mem, BIO_NOCLOSE) <= 0)
		errx(1, "BIO_set_mem_buf");
	if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) == 0)
		errx(1, "PEM_write_bio_PrivateKey");
	if (BIO_free(bio) == 0)
		errx(1, "BIO_free");
	*key = mem.data;
	*key_size = mem.length;

	/*
	 * Generate self sign certificate.
	 */
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

	/* Get memory pointer of certificate. */
	memset(&mem, 0, sizeof mem);
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		errx(1, "BIO_new");
	if (BIO_set_mem_buf(bio, &mem, BIO_NOCLOSE) <= 0)
		errx(1, "BIO_set_mem_buf");
	if (PEM_write_bio_X509(bio, x509) == 0)
		err(1, "PEM_write_bio_X509");
	if (BIO_free(bio) == 0)
		errx(1, "BIO_free");
	*crt = mem.data;
	*crt_size = mem.length;

	X509_free(x509);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
}

int
server(struct sockaddr_in *sin)
{
	struct server	 server;
	uint8_t		*crt = NULL;
	uint8_t		*key = NULL;
	size_t		 key_size;
	size_t		 crt_size;
	int		 c;

	memset(&server, 0, sizeof server);

	fprintf(stderr, "server\n");

	/*
	 * TLS preparation
	 */

	if ((server.tls = tls_server()) == NULL)
		err(1, "tls_server");

	if ((server.config = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	/* Generate key with selfsigned certificate. */
	generate_cert(&key, &key_size, &crt, &crt_size);
	if (tls_config_set_key_mem(server.config, key, key_size) == -1)
		errx(1, "%s", tls_config_error(server.config));
	if (tls_config_set_cert_mem(server.config, crt, crt_size) == -1)
		errx(1, "%s", tls_config_error(server.config));

	if (tls_configure(server.tls, server.config) == -1)
		err(1, "tls_configure");

	/*
	 * Socket Handling
	 */

	if ((server.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	if (setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR,
	    (int [1]){1}, sizeof(int *)) == -1)
		err(1, "setsockopt");

	if (bind(server.fd, (struct sockaddr *)sin, sizeof *sin) == -1)
		err(1, "bind");

	if (listen(server.fd, 10) == -1)
		err(1, "listen");

	for (;;) {
		struct tls *ctx;

		if ((c = accept(server.fd, NULL, NULL)) == -1)
			err(1, "accept");

		if (tls_accept_socket(server.tls, &ctx, c) == -1)
			err(1, "tls_accept_socket: %s", tls_error(server.tls));

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
	int			 fd;
	int			 data;

	fprintf(stderr, "client\n");

	if ((tls = tls_client()) == NULL)
		err(1, "tls_server");

	if ((config = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	/* Don't check server certificate. */
	tls_config_insecure_noverifyname(config);
	tls_config_insecure_noverifycert(config);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	if (connect(fd, (struct sockaddr *)sin, sizeof *sin) == -1)
		err(1, "connect");

	if (tls_connect_socket(tls, fd, "localhost") == -1)
		err(1, "tls_connect_socket: %s", tls_error(tls));

	if (read(fd, &data, sizeof data) != 0)
		err(1, "read");

	if (close(fd) == -1)
		err(1, "close");

	return 0;
}

void
usage(void)
{
	fprintf(stderr, "tlsbench [-l] [address] [port]\n");
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in	 sin;
	const char		*errstr;
	char			*addr = "127.0.0.1";
	char			*port = "12345";
	bool			 lflag = false;
	int			 ch;

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
	sin.sin_len = sizeof sin;
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
		return server(&sin);

	return client(&sin);
}
