/*
 * Build a binary data file that looks like what the ACPI BERT (Boot
 * Error Record Table) expects to read.  This is to be used in testing
 * the BERT functionality in qemu.
 *
 * So, build up an ESB (Error Status Block) with a bunch of records, and
 * at least one of each type, then print it out.
 *
 * Much of this code (especially ACPI header tables and CPER printing) has
 * been borrowed directly from Linux.
 *
 * The format of an ESB is something like this:
 * +------------------------------------------------------------------+
 * | struct acpi_hest_generic_status:                                 |
 * |     ...							      |
 * |     +-----------------------------------------------------------+|
 * |     | struct acpi_hest_generic_data[0]                          ||
 * |     +-----------------------------------------------------------+|
 * |     | struct acpi_hest_generic_data[1]                          ||
 * |     +-----------------------------------------------------------+|
 * |     | ....                                                      ||
 * |     +-----------------------------------------------------------+|
 * |     | raw error data                                            ||
 * |     |    ...                                                    ||
 * |     +-----------------------------------------------------------+|
 * +------------------------------------------------------------------+
 * | struct acpi_hest_generic_status:                                 |
 * |     ...							      |
 *
 * There can be multiple acpi_hest_generic_status blocks, one following
 * the other.  There can be zero or more acpi_hest_generic_data structs;
 * there may or may not be any raw error data.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mkesb.h"

void build_generic_status(struct acpi_hest_generic_status *s)
{
	memset(s, 0xbb, sizeof(*s));
	return;
}

void esb_print_all(struct acpi_bert_region *region, unsigned int region_len)
{
	struct acpi_hest_generic_status *estatus =
		(struct acpi_hest_generic_status *)region;
	int remain = region_len;
	u32 estatus_len;

	if (!estatus->block_status)
		return;

	while (remain > sizeof(struct acpi_bert_region)) {
		if (cper_estatus_check(estatus)) {
			printf("? Invalid error record.\n");
			return;
		}

		estatus_len = cper_estatus_len(estatus);
		if (remain < estatus_len) {
			printf("? Truncated status block (length: %u).\n",
			       estatus_len);
			return;
		}

		printf("Error records from previous boot:\n");

		cper_estatus_print(PFX, estatus);

		/*
		 * Because the boot error source is "one-time polled" type,
		 * clear Block Status of current Generic Error Status Block,
		 * once it's printed.
		 */
		estatus->block_status = 0;

		estatus = (void *)estatus + estatus_len;
		/* No more error records. */
		if (!estatus->block_status)
			return;

		remain -= estatus_len;
	}
}

int main(int argc, char *argv[])
{
	int ret;
	int fd;
	int count;
	unsigned char *cur;
	unsigned char *esb;
	char *fname;
	mode_t mode;
	char buf[BUFLEN];

	struct acpi_hest_generic_status status;

	/* initialization */
	ret = 0;
	if (argc > 1 && argv[1])
		fname = argv[1];
	else {
		printf("? output file name is required.\n");
		exit(1);
	}

	/* set up a big block of empty memory to put an ESB in */
	esb = (unsigned char *)calloc(ESB_SIZE, 1);
	if (!esb) {
		printf("? cannot calloc %d bytes.\n", ESB_SIZE);
		exit(1);
	}

	/* fill out the ESB */
	cur = esb;
	cur[0] = 0xde;
	cur[1] = 0xad;
	cur[2] = 0xbe;
	cur[3] = 0xef;
	cur += 4;

	build_generic_status(&status);
	memcpy(cur, &status, sizeof(status));
	cur += sizeof(status);

	/* print out what we just did */
	esb_print_all((struct acpi_bert_region *)esb,
		      (unsigned int)(cur - esb));

	/* write out the results */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
	fd = open(fname, O_CREAT | O_TRUNC | O_RDWR, mode);
	if (fd < 0) {
		memset(buf, 0, BUFLEN);
		sprintf(buf, "? cannot open file %s", fname);
		perror(buf);
		free(esb);
		exit(1);
	}
	count = write(fd, esb, ESB_SIZE);
	if (count < 0) {
		perror("? ESB write failed");
		free(esb);
		exit(1);
	}
	close(fd);
	printf("wrote %d bytes.\n", count);

	/* all done */
	free(esb);
	return ret;
}
