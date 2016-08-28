#ifndef _MKESB_H
#define _MKESB_H

#include <stdint.h>

/* borrowed from ACPICA */
#define COMPILER_DEPENDENT_INT64 int64_t
#define COMPILER_DEPENDENT_UINT64 uint64_t
#define ACPI_MACHINE_WIDTH 64
#define ACPI_SYSTEM_XFACE

#include "actypes.h"
#include "actbl.h"
#include "actbl1.h"
/* end */

/* borrowed from Linux */
enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};

extern void print_hex_dump(const char *prefix_str, int prefix_type,
		    	   int rowsize, int groupsize,
		    	   const void *buf, int len, int ascii);

#include "cper.h"
/* end */

#define BUFLEN		0x400
#define ESB_SIZE	0x10000
#define PFX		"MKESB"

#endif
