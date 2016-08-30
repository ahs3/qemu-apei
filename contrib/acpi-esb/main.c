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

#define NO_UUID UUID_LE(0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0)

struct section_type_args st_args[] = {
   { "procgen", ST_PROCGEN, CPER_SEC_PROC_GENERIC, "processor generic" },
   { "procx86", ST_PROCX86, CPER_SEC_PROC_IA, "processor specific, x86" },
   { "procipf", ST_PROCIPF, CPER_SEC_PROC_IPF, "processor specific, ia64" },
   { "procarm", ST_PROCARM, CPER_SEC_PROC_ARMV8, "processor specific, arm64" },
   { "mem", ST_MEM, CPER_SEC_PLATFORM_MEM, "platform memory" },
   { "pcie", ST_PCIE, CPER_SEC_PCIE, "PCIe" },
   { "fw", ST_FW, CPER_SEC_FW_ERR_REC_REF, "Firmware Error Record Reference" },
   { "pcibus", ST_PCIBUS, CPER_SEC_PCI_X_BUS, "PCI/PCI-X bus" },
   { "pcidev", ST_PCIDEV, CPER_SEC_PCI_DEV, "PCI component/device" },
   { "dmar", ST_DMAR, CPER_SEC_DMAR_GENERIC, "DMAR generic" },
   { "intelvt", ST_INTELVT, CPER_SEC_DMAR_VT, "Intel VT for DMAR" },
   { "iommu", ST_IOMMU, CPER_SEC_DMAR_IOMMU, "IOMMU specific DMAR section" },
   { "no such type", ST_NO_SUCH_TYPE, NO_UUID, "no such type" }
};

struct section_type_args *find_st_args(char *val)
{
	struct section_type_args *p = &st_args[0];

	while (p->num != ST_NO_SUCH_TYPE) {
		if (strcmp(p->name, val) == 0)
			break;
		p++;
	}
	return p;
}

void usage (const char *prog)
{
	printf("%s, v0.1.11\n", prog);
	printf("usage: %s %s %s %s %s %s\n\t%s %s <filename>\n",
	       prog, "[-2]", "[-e <count>]", "[-f <filename>]", "[-h]",
	       "[-s <section-type>]", "[-S {0|1|2|3}]", "[-F <mask>]");
	printf("where:\n");
	printf("   -2			=> use revision prior to 0x300 for generic data\n");
	printf("   			   (0x300 is the default format)\n");
	printf("   -e <count>		=> number of ESB(s) to write (default: 1)\n");
	printf("   -f <filename>	=> file to write ESB(s) to\n");
	printf("   -F <mask>		=> 1 byte bit field for generic error flags\n");
	printf("   -g <count>		=> number of generic error data entries to write\n");
	printf("   			   per ESB (default: 1)\n");
	printf("   -h			=> print this help message\n");
	printf("   -s <section-type>	=> choose one of: procgen, proc86, procipf,\n");
	printf("   			   procarm, mem, pcie, fw, pcibus, pcidev,\n");
	printf("   			   dmar, intelvt, iommu\n");
	printf("   -S <severity>	=> 0: recoverable, 1: fatal, 2: corrected,\n");
	printf("   			   3: none (default: 3)\n");
}

int test_size(const unsigned char *cur, const unsigned char *esb, int more)
{
	return ((unsigned int)(cur - esb) + more > ESB_SIZE) ? 1 : 0;
}

int main(int argc, char *argv[])
{
	int ret;
	int fd;
	int count;
	int ii, jj;
	unsigned char *cur;
	unsigned char *esb, *last_esb;
	mode_t mode;
	char buf[BUFLEN];
	char *yn;

	const char *opts = "2e:f:F:g:hs:S:";
	int opt;
	int esb_count = 1;
	int generic_data_count = 1;
	int use_generic_v300 = 1;	/* true, by default */
	char *fname = NULL;
	struct section_type_args *stype = &st_args[ST_NO_SUCH_TYPE];
	int gensev = 3;		/* generic error severity, default: no error */
	u8 flags = CPER_SEC_PRIMARY;

	struct acpi_hest_generic_status status;
	struct acpi_hest_generic_data_v300 gendata_v300;  /* use the big one */
	struct esb_geninfo entry;

	/* initialization */
	ret = 0;
	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}
	while ((opt = getopt(argc, argv, opts)) != -1) {
		switch (opt) {
		case '2':
			use_generic_v300 = 0;
			break;
		case 'e':
			esb_count = atoi(optarg);
			break;
		case 'f':
			fname = optarg;
			break;
		case 'F':
			flags = strtol(optarg, NULL, 0);
			break;
		case 'g':
			generic_data_count = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(1);
		case 's':
			stype = find_st_args(optarg);
			if (stype->num == ST_NO_SUCH_TYPE) {
				printf("? no such section type: %s\n", optarg);
				exit(1);
			}
			break;
		case 'S':
			gensev = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}
	if (!fname)
		fname = argv[optind];

	if (!fname) {
		printf("? a file name is required\n");
		exit(1);
	}

	printf("Command line:\n");
	printf("  ESB(s) to create: %d\n", esb_count);
	yn = use_generic_v300 ? "yes" : "no";
	printf("  Use revision 0x300 format for generic error data: %s\n", yn);
	printf("  Generic error data entries to create: %d\n", generic_data_count);
	printf("  Use section type: %s, \"%s\"\n", stype->name, stype->desc);
	printf("  Use generic error severity: %d\n", gensev);
	printf("  Use generic error flags: 0x%02x\n", flags);
	printf("  Results in file: %s\n", fname);

	/* set up a big block of empty memory to put an ESB in */
	esb = (unsigned char *)calloc(ESB_SIZE, 1);
	if (!esb) {
		printf("? cannot calloc %d bytes.\n", ESB_SIZE);
		exit(1);
	}

	/* fill out the ESB(s) */
	cur = esb;
	for (ii = 0; ii < esb_count; ii++) {
		if (test_size(cur, esb, sizeof(status)))
			break;
		if (build_generic_status(&status)) {
			memcpy(cur, &status, sizeof(status));
			last_esb = cur;
			cur += sizeof(status);
			printf("wrote ESB %d\n", ii + 1);
		}

		/* fill out the generic error data */
		for (jj = 0; jj < generic_data_count; jj++) {
			if (test_size(cur, esb, sizeof(gendata_v300)))
				break;
			entry.gendata = &gendata_v300;
			entry.use_v300 = use_generic_v300;
			entry.stype = stype;
			entry.severity = gensev;
			entry.flags = flags;
			if (build_generic_data(&entry)) {
				memcpy(cur, entry.gendata, entry.actual_size);
				cur += entry.actual_size;
				printf("- wrote generic data entry %d\n",
				       jj + 1);
				add_generic_data(last_esb, &entry);
			}
		}
	}

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
