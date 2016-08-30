#ifndef _ESB_H
#define _ESB_H

#include "mkesb.h"

extern int build_generic_status(struct acpi_hest_generic_status *s);

enum section_type {
	ST_PROCGEN,	/* processor generic */
	ST_PROCX86,	/* processor specific, ia32/x64 */
	ST_PROCIPF,	/* processor specific, IPF */
	ST_PROCARM,	/* processor specific, ARM */
	ST_MEM,		/* platform memory */
	ST_PCIE,	/* PCIe */
	ST_FW,		/* Firmware Error Record Reference */
	ST_PCIBUS,	/* PCI/PCI-X bus */
	ST_PCIDEV,	/* PCI Component/Device */
	ST_DMAR,	/* DMAR generic */
	ST_INTELVT,	/* Intel VT for DMAR */
	ST_IOMMU,	/* IOMMU specific DMAR section */
	ST_NO_SUCH_TYPE
};

struct section_type_args {
	char *name;	/* from the option */
	int  num;	/* from the enum */
	uuid_le guid;
	char *desc;
};

struct esb_geninfo {
	void *gendata;		/* generic data entry to fill */
	int use_v300;		/* true for rev 0x300 structs */
	int actual_size;	/* actual struct size (depends on v300 */
	struct section_type_args *stype;	/* section type info */
	int severity;		/* generic error severity */
	u8 flags;		/* generic error flags */
};

extern int build_generic_data(struct esb_geninfo *entry);
extern void add_generic_data(unsigned char *cur_esb, struct esb_geninfo *entry);

#endif
