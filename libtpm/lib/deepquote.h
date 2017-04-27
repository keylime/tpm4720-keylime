/* Aggregate some useful functions here */
#ifndef  DEEPQUOTE_H
#define  DEEPQUOTE_H
#include <errno.h>

/* vTPM command params */
#define VTPM_QUOTE_FLAGS_HASH_UUID                  0x00000001
#define VTPM_QUOTE_FLAGS_VTPM_MEASUREMENTS          0x00000002
#define VTPM_QUOTE_FLAGS_GROUP_INFO                 0x00000004
#define VTPM_QUOTE_FLAGS_GROUP_PUBKEY               0x00000008

extern unsigned int TPM_logflag;

/* Some debugging prints */
#define dump_bytes(arr,name, n)					\
    do {							\
	if (TPM_logflag) {					\
	    int i;						\
	    for (i=0; i < (int)(n); i++) {			\
		if ((i % 20) == 0) {				\
		    printf("\n%s[%d]: ", name, i/20);		\
		}						\
		printf("%02x ", ((unsigned char *)arr)[i]);	\
	    }							\
	    printf("\n");					\
	}							\
    } while(0)

#define dump_hash(arr, name) dump_bytes(arr, name, 20)
#define logfprintf(...)				\
    do {					\
	if (TPM_logflag) {			\
	    fprintf(__VA_ARGS__);		\
	}					\
    } while(0)

/* Convenience macros for arg checking */
#define printExitCode(rc, ...) do {		\
    fprintf(stderr, __VA_ARGS__);		\
    exit(rc);					\
    } while(0)
#define printExit(...) printExitCode(-1, __VA_ARGS__)

#define CHECK_ARG(arg, name) do {				\
	if ((arg) == 0)	{					\
	    printf("Required argument '" name "' missing\n");	\
	    printUsage();					\
	}							\
    } while(0)

/* Headers used in the hashed QuoteInfo structs */
static const BYTE dquot_hdr[] = {
	0, 0, 0, 0, 'D', 'Q', 'U', 'T'
};

static const BYTE quot_hdr[] = {
	1, 1, 0, 0, 'Q', 'U', 'O', 'T'
};

/* Some redefinitions of TPM structures that are easier to serialize without TSS_* stuff */
struct __attribute__ ((packed)) PCR_SELECTION {
    uint16_t sizeOfSelect;
    BYTE pcrSelect[3];
};
struct __attribute__ ((packed)) PCR_INFO_SHORT {
    struct PCR_SELECTION pcrSelection;
    TPM_LOCALITY_SELECTION localityAtRelease;
    TPM_COMPOSITE_HASH digestAtRelease;
};

typedef struct __attribute__ ((packed)) DeepQuoteValues {
    uint32_t numInfoHashes;
    unsigned char infoHashes[4 * TPM_HASH_SIZE];
    uint32_t numPCRVals;
    unsigned char PCRVals[24 * TPM_HASH_SIZE];
} DeepQuoteValues;

typedef struct __attribute__ ((packed)) DeepQuoteInfo  {
    unsigned char  extraInfoFlags[4];
    unsigned char  signature[256];
    DeepQuoteValues values;
} DeepQuoteInfo;

/* Structure representing a serialized DeepQuote */
struct __attribute__ ((packed)) DeepQuoteBin {
	struct PCR_SELECTION ppcrSel;
	DeepQuoteInfo dqi;
};

/**
 * read_file() - Read a file into a heap-allocated buffer
 * @path:	The filepath
 * @size:	The amount of bytes to read
 *
 * Allocates a buffer of size @len and fills it with the first @len
 * bytes of the file at @path. The caller is responsible for freeing
 * the allocated buffer.
 *
 * Return: Buffer containing the first @len bytes of @path on
 * success. Exits on failure.
 */
__attribute__ ((unused)) /* Leave me alone gcc */
static unsigned char *read_file(const char *path, size_t len)
{
    FILE *fp;
    unsigned char *buf = calloc(1, len);
    size_t bytes_read = 0;

    if ((fp = fopen(path,"rb"))==0) {
	printf("Error opening file '%s'\n", path);
	exit(ENOENT);
    }

    if ((bytes_read = fread(buf, 1, len, fp)) != len) {
	printf("Only read %zu out of %zu requested\n", bytes_read, len);
	exit(EINVAL);
    }
    fclose(fp);

    return buf;
}

#endif /* !(DEEPQUOTE_H) */
