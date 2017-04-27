/* Convert TPM Modulus files to PEM */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"
#include "tpm_error.h"


static void usage() {
	printf("Usage: -ik [filename] -ok [filename]\n");
	printf("\n");
	printf(" -ik <keyname>: Key file name (raw modulus file)\n");
	printf(" -ok <keyname>: Key file name\n");
	printf("\n");
	exit(-1);
}


struct modulus {
	size_t len;
	unsigned char data[256];
};

static int filesize(FILE *fp)
{
	size_t cur_pos = ftell(fp);
	size_t size;
	assert(fseek(fp, 0, SEEK_END) == 0);

	size = ftell(fp);
	assert(fseek(fp, cur_pos, SEEK_SET) == 0);

	return size;
}

#define write_file(filename, data, len) do {				\
	FILE *fp;							\
	if ((fp = fopen(filename, "wb")) == 0) {			\
		fprintf(fp, "Unable to open '%s' - %s", filename, strerror(errno)); \
		return errno;						\
	}								\
	if (fwrite(data, 1, len, fp) != len) {				\
		fprintf(fp, "Failed to write all %zu bytes of '%s'\n", len, filename); \
		return errno;						\
	}								\
	fclose(fp);							\
	} while(0)


static int check_filesize(FILE *fp, size_t goal_size)
{
	size_t actual_size = filesize(fp);
	return (goal_size == actual_size)?0:actual_size;
}

static pubkeydata *mod_to_pkey(struct modulus *modulus)
{
	pubkeydata *pkey = calloc(1, sizeof(*pkey));

	/* Set up the parameters */
	pkey->algorithmParms.algorithmID = TPM_ALG_RSA;
	pkey->algorithmParms.encScheme = TPM_ES_NONE;
	pkey->algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
	pkey->algorithmParms.u.rsaKeyParms.keyLength = 2048;
	pkey->algorithmParms.u.rsaKeyParms.numPrimes = 2;
	pkey->algorithmParms.u.rsaKeyParms.exponentSize = 0;

	/* Copy the modulus to the pubkeydata */
	assert(modulus->len <= sizeof(pkey->pubKey.modulus));
	memcpy(pkey->pubKey.modulus, modulus->data, modulus->len);
	pkey->pubKey.keyLength = modulus->len;

	fprintf(stderr, "Final size of pubkeydata is %zu\n", sizeof(*pkey));
	return pkey;
}


static int tpmconv(struct modulus *modulus, const char *pempath)
{
	int ret = -1;
	FILE *fp = NULL;
	pubkeydata *pkey;
	EVP_PKEY *evp_pkey = NULL;
	RSA *rsa;
	pkey = mod_to_pkey(modulus);

	rsa = TSS_convpubkey(pkey);

	if (rsa == NULL) {
		ret = 1;
		goto error;
	}

	if ((fp = fopen(pempath, "wb")) == 0) {
		fprintf(stderr, "Unable to open '%s'\n", pempath);
		return errno;
	}

	OpenSSL_add_all_algorithms();
	evp_pkey = EVP_PKEY_new();
	if (evp_pkey == NULL) {
		fprintf(stderr, "Unable to create EVP_PKEY\n");
		ERR_print_errors_fp(stderr);
		ret = (int)ERR_get_error();
		goto error;
	}

	if (EVP_PKEY_assign_RSA(evp_pkey, rsa) == 0) {
		fprintf(stderr, "Unable to assign RSA to EVP_PKEY\n");
		ERR_print_errors_fp(stderr);
		ret = (int)ERR_get_error();
		goto error;
	}

	if (PEM_write_PUBKEY(fp, evp_pkey) == 0) {
		fprintf(stderr, "Unable to write pubkey\n");
		ERR_print_errors_fp(stderr);
		ret = (int)ERR_get_error();
		goto error;
	}

	fprintf(stdout, "Wrote '%s'\n", pempath);
	ret = 0;

error:
	EVP_PKEY_free(evp_pkey);
	fclose(fp);
	return ret;
}

int main(int argc, char *argv[])
{
	const char *inkey  = NULL;
	const char *outkey = NULL;
	FILE *fp;
	int i;
	struct modulus modulus = {
		.len = 256
	};

	if (argc < 2)
		usage();

	for (i = 0 ; i < argc; i++) {
		if (strcmp(argv[i], "-ik") == 0) {
			if (i >= (argc-1)) {
				fprintf(stderr, "-ik Requires argument\n");
				exit(-1);
			}
			inkey = argv[++i];
		}

		if (strcmp(argv[i], "-ok") == 0) {
			if (i >= (argc-1)) {
				fprintf(stderr, "-ok Requires argument\n");
				exit(-1);
			}
			outkey = argv[++i];
		}
	}

	if (inkey == NULL)
		usage();

	if ((fp = fopen(inkey, "rb")) == 0) {
		fprintf(stderr, "Failed to open '%s'", inkey);
		exit(-1);
	}
	if (check_filesize(fp, 256) != 0) {
		size_t size = filesize(fp);
		fprintf(stderr, "Expected 256 byte file, got %zu byte file\n", size);
		fclose(fp);
		exit(-1);
	}

	if (fread(modulus.data, 1, sizeof(modulus.data), fp) != sizeof(modulus.data)) {
		fprintf(stderr, "Failed to read from '%s'\n", inkey);
		fclose(fp);
		exit(-1);
	}

	fclose(fp);

	if (outkey == NULL)
		outkey = "key";

	return tpmconv(&modulus, outkey);
}
