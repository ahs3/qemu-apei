/*
 * UEFI Common Platform Error Record (CPER) support
 *
 * Copyright (C) 2010, Intel Corp.
 *	Author: Huang Ying <ying.huang@intel.com>
 *
 * CPER is the format used to describe platform hardware error by
 * various tables, such as ERST, BERT and HEST etc.
 *
 * For more information about CPER, please refer to Appendix N of UEFI
 * Specification version 2.4.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "mkesb.h"

#include <errno.h>
#include <stdio.h>
#include <time.h>

/*
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/dmi.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/printf.h>
#include <linux/bcd.h>
#include <ras/ras_event.h>
*/

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define INDENT_SP	" "

#define acpi_hest_generic_data_version(gdata)		\
	(gdata->revision >> 8)

static char rcd_decode_str[CPER_REC_LEN];

static int uuid_le_cmp(const uuid_le u1, const uuid_le u2)
{
	return memcmp(&u1, &u2, sizeof(uuid_le));
}

static void *acpi_hest_generic_data_payload(
					struct acpi_hest_generic_data *gdata)
{
	return acpi_hest_generic_data_version(gdata) >= 3 ?
		(void *)(((struct acpi_hest_generic_data_v300 *)(gdata)) + 1) :
		gdata + 1;
}

static unsigned bcd2bin(unsigned char val)
{
        return (val & 0x0f) + (val >> 4) * 10;
}

/*
 * CPER record ID need to be unique even after reboot, because record
 * ID is used as index for ERST storage, while CPER records from
 * multiple boot may co-exist in ERST.
 */
/*
u64 cper_next_record_id(void)
{
	static u64 seq;

	if (!seq)
		seq = (u64)time(NULL) << 32;
	return ++seq;
}
*/

static const char * const severity_strs[] = {
	"recoverable",
	"fatal",
	"corrected",
	"info",
};

const char *cper_severity_str(unsigned int severity)
{
	return severity < ARRAY_SIZE(severity_strs) ?
		severity_strs[severity] : "unknown";
}

/*
 * cper_print_bits - print strings for set bits
 * @pfx: prefix for each line, including log level and prefix string
 * @bits: bit mask
 * @strs: string array, indexed by bit position
 * @strs_size: size of the string array: @strs
 *
 * For each set bit in @bits, print the corresponding string in @strs.
 * If the output length is longer than 80, multiple line will be
 * printed, with @pfx is printed at the beginning of each line.
 */
void cper_print_bits(const char *pfx, unsigned int bits,
		     const char * const strs[], unsigned int strs_size)
{
	int i, len = 0;
	const char *str;
	char buf[84];

	for (i = 0; i < strs_size; i++) {
		if (!(bits & (1U << i)))
			continue;
		str = strs[i];
		if (!str)
			continue;
		if (len && len + strlen(str) + 2 > 80) {
			printf("%s\n", buf);
			len = 0;
		}
		if (!len)
			len = snprintf(buf, sizeof(buf), "%s%s", pfx, str);
		else
			len += snprintf(buf+len, sizeof(buf)-len, ", %s", str);
	}
	if (len)
		printf("%s\n", buf);
}

static const char * const proc_type_strs[] = {
	"IA32/X64",
	"IA64",
	"ARMv8",
};

static const char * const proc_isa_strs[] = {
	"IA32",
	"IA64",
	"X64",
	"ARM A32/T32",
	"ARM A64",
};

static const char * const proc_error_type_strs[] = {
	"cache error",
	"TLB error",
	"bus error",
	"micro-architectural error",
};

static const char * const proc_op_strs[] = {
	"unknown or generic",
	"data read",
	"data write",
	"instruction execution",
};

static const char * const proc_flag_strs[] = {
	"restartable",
	"precise IP",
	"overflow",
	"corrected",
};

static void cper_print_proc_generic(const char *pfx,
				    const struct cper_sec_proc_generic *proc)
{
	if (proc->validation_bits & CPER_PROC_VALID_TYPE)
		printf("%s""processor_type: %d, %s\n", pfx, proc->proc_type,
		       proc->proc_type < ARRAY_SIZE(proc_type_strs) ?
		       proc_type_strs[proc->proc_type] : "unknown");
	if (proc->validation_bits & CPER_PROC_VALID_ISA)
		printf("%s""processor_isa: %d, %s\n", pfx, proc->proc_isa,
		       proc->proc_isa < ARRAY_SIZE(proc_isa_strs) ?
		       proc_isa_strs[proc->proc_isa] : "unknown");
	if (proc->validation_bits & CPER_PROC_VALID_ERROR_TYPE) {
		printf("%s""error_type: 0x%02x\n", pfx, proc->proc_error_type);
		cper_print_bits(pfx, proc->proc_error_type,
				proc_error_type_strs,
				ARRAY_SIZE(proc_error_type_strs));
	}
	if (proc->validation_bits & CPER_PROC_VALID_OPERATION)
		printf("%s""operation: %d, %s\n", pfx, proc->operation,
		       proc->operation < ARRAY_SIZE(proc_op_strs) ?
		       proc_op_strs[proc->operation] : "unknown");
	if (proc->validation_bits & CPER_PROC_VALID_FLAGS) {
		printf("%s""flags: 0x%02x\n", pfx, proc->flags);
		cper_print_bits(pfx, proc->flags, proc_flag_strs,
				ARRAY_SIZE(proc_flag_strs));
	}
	if (proc->validation_bits & CPER_PROC_VALID_LEVEL)
		printf("%s""level: %d\n", pfx, proc->level);
	if (proc->validation_bits & CPER_PROC_VALID_VERSION)
		printf("%s""version_info: 0x%016lx\n", pfx, proc->cpu_version);
	if (proc->validation_bits & CPER_PROC_VALID_ID)
		printf("%s""processor_id: 0x%016lx\n", pfx, proc->proc_id);
	if (proc->validation_bits & CPER_PROC_VALID_TARGET_ADDRESS)
		printf("%s""target_address: 0x%016lx\n",
		       pfx, proc->target_addr);
	if (proc->validation_bits & CPER_PROC_VALID_REQUESTOR_ID)
		printf("%s""requestor_id: 0x%016lx\n",
		       pfx, proc->requestor_id);
	if (proc->validation_bits & CPER_PROC_VALID_RESPONDER_ID)
		printf("%s""responder_id: 0x%016lx\n",
		       pfx, proc->responder_id);
	if (proc->validation_bits & CPER_PROC_VALID_IP)
		printf("%s""IP: 0x%016lx\n", pfx, proc->ip);
}

static void cper_print_proc_armv8(const char *pfx,
				  const struct cper_sec_proc_armv8 *proc)
{
	int i, len;
	struct cper_armv8_err_info *err_info;
	__u64 *qword = NULL;
	char newpfx[64];

	printf("%ssection length: %d\n", pfx, proc->section_length);
	printf("%sMIDR: 0x%016lx\n", pfx, proc->midr);

	len = proc->section_length - (sizeof(*proc) +
		proc->err_info_num * (sizeof(*err_info)));
	if (len < 0) {
		printf("%ssection length is too small.\n", pfx);
		printf("%sERR_INFO_NUM is %d.\n", pfx, proc->err_info_num);
		return;
	}

	if (proc->validation_bits & CPER_ARMV8_VALID_MPIDR)
		printf("%sMPIDR: 0x%016lx\n", pfx, proc->mpidr);
	if (proc->validation_bits & CPER_ARMV8_VALID_AFFINITY_LEVEL)
		printf("%serror affinity level: %d\n", pfx,
			proc->affinity_level);
	if (proc->validation_bits & CPER_ARMV8_VALID_RUNNING_STATE) {
		printf("%srunning state: %d\n", pfx, proc->running_state);
		printf("%sPSCI state: %d\n", pfx, proc->psci_state);
	}

	snprintf(newpfx, sizeof(newpfx), "%s%s", pfx, INDENT_SP);

	err_info = (struct cper_armv8_err_info *)(proc + 1);
	for (i = 0; i < proc->err_info_num; i++) {
		printf("%sError info structure %d:\n", pfx, i);
		printf("%sversion:%d\n", newpfx, err_info->version);
		printf("%slength:%d\n", newpfx, err_info->length);
		if (err_info->validation_bits &
		    CPER_ARMV8_INFO_VALID_MULTI_ERR) {
			if (err_info->multiple_error == 0)
				printf("%ssingle error.\n", newpfx);
			else if (err_info->multiple_error == 1)
				printf("%smultiple errors.\n", newpfx);
			else
				printf("%smultiple errors count:%d.\n",
				newpfx, err_info->multiple_error);
		}
		if (err_info->validation_bits & CPER_ARMV8_INFO_VALID_FLAGS) {
			if (err_info->flags & CPER_ARMV8_INFO_FLAGS_FIRST)
				printf("%sfirst error captured.\n", newpfx);
			if (err_info->flags & CPER_ARMV8_INFO_FLAGS_LAST)
				printf("%slast error captured.\n", newpfx);
			if (err_info->flags & CPER_ARMV8_INFO_FLAGS_PROPAGATED)
				printf("%spropagated error captured.\n",
				       newpfx);
		}
		printf("%serror_type: %d, %s\n", newpfx, err_info->type,
			err_info->type < ARRAY_SIZE(proc_error_type_strs) ?
			proc_error_type_strs[err_info->type] : "unknown");
		printf("%serror_info: 0x%016lx\n", newpfx,
		       err_info->error_info);
		if (err_info->validation_bits & CPER_ARMV8_INFO_VALID_VIRT_ADDR)
			printf("%svirtual fault address: 0x%016lx\n",
				newpfx, err_info->virt_fault_addr);
		if (err_info->validation_bits &
		    CPER_ARMV8_INFO_VALID_PHYSICAL_ADDR)
			printf("%sphysical fault address: 0x%016lx\n",
				newpfx, err_info->physical_fault_addr);
		/* TODO: where did this come from???
		trace_arm_event(proc->affinity_level, proc->mpidr, proc->midr,
				proc->running_state, proc->psci_state,
				err_info->version, err_info->type,
				err_info->multiple_error,
				err_info->validation_bits,
				err_info->error_info,
				err_info->virt_fault_addr,
				err_info->physical_fault_addr);
		*/
		err_info += 1;
	}

	if (len < sizeof(*qword) && proc->context_info_num > 0) {
		printf("%ssection length is too small.\n", pfx);
		printf("%sCTX_INFO_NUM is %d.\n", pfx, proc->context_info_num);
		return;
	}
	for (i = 0; i < proc->context_info_num; i++) {
		qword = (__u64 *)err_info;
		printf("%sProcessor context info structure %d:\n", pfx, i);
		printf("%sException level %d.\n", newpfx,
		       (int)((*qword & CPER_ARMV8_CTX_EL_MASK)
				>> CPER_ARMV8_CTX_EL_SHIFT));
		printf("%sSecure bit: %d.\n", newpfx,
		       (int)((*qword & CPER_ARMV8_CTX_NS_MASK)
				>> CPER_ARMV8_CTX_NS_SHIFT));
		if ((*qword & CPER_ARMV8_CTX_TYPE_MASK) == 0) {
			if (len < CPER_AARCH32_CTX_LEN) {
				printf("%ssection length is too small.\n", pfx);
				printf("%sremaining length is %d.\n", pfx, len);
				return;
			}
			printf("%sAArch32 execution context.\n", newpfx);
			qword++;
			print_hex_dump(newpfx, DUMP_PREFIX_OFFSET, 16, 4,
				qword, CPER_AARCH32_CTX_LEN - sizeof(*qword),
				0);
			len -= CPER_AARCH32_CTX_LEN;
		} else if ((*qword & CPER_ARMV8_CTX_TYPE_MASK) == 1) {
			if (len < CPER_AARCH64_CTX_LEN) {
				printf("%ssection length is too small.\n", pfx);
				printf("%sremaining length is %d.\n", pfx, len);
				return;
			}
			printf("%sAArch64 execution context.\n", newpfx);
			qword++;
			print_hex_dump(newpfx, DUMP_PREFIX_OFFSET, 16, 4,
				qword, CPER_AARCH64_CTX_LEN - sizeof(*qword),
				0);
			len -= CPER_AARCH64_CTX_LEN;
		} else {
			printf("%scontext type is incorrect 0x%016llx.\n",
			pfx, *qword);
			return;
		}
	}

	if (len > 0) {
		printf("%sVendor specific error info has %d bytes.\n", pfx,
		       len);
		print_hex_dump(pfx, DUMP_PREFIX_OFFSET, 16, 4, qword, len,
			0);
	}
}

static const char * const mem_err_type_strs[] = {
	"unknown",
	"no error",
	"single-bit ECC",
	"multi-bit ECC",
	"single-symbol chipkill ECC",
	"multi-symbol chipkill ECC",
	"master abort",
	"target abort",
	"parity error",
	"watchdog timeout",
	"invalid address",
	"mirror Broken",
	"memory sparing",
	"scrub corrected error",
	"scrub uncorrected error",
	"physical memory map-out event",
};

const char *cper_mem_err_type_str(unsigned int etype)
{
	return etype < ARRAY_SIZE(mem_err_type_strs) ?
		mem_err_type_strs[etype] : "unknown";
}

static int cper_mem_err_location(struct cper_mem_err_compact *mem, char *msg)
{
	u32 len, n;

	if (!msg)
		return 0;

	n = 0;
	len = CPER_REC_LEN - 1;
	if (mem->validation_bits & CPER_MEM_VALID_NODE)
		n += snprintf(msg + n, len - n, "node: %d ", mem->node);
	if (mem->validation_bits & CPER_MEM_VALID_CARD)
		n += snprintf(msg + n, len - n, "card: %d ", mem->card);
	if (mem->validation_bits & CPER_MEM_VALID_MODULE)
		n += snprintf(msg + n, len - n, "module: %d ", mem->module);
	if (mem->validation_bits & CPER_MEM_VALID_RANK_NUMBER)
		n += snprintf(msg + n, len - n, "rank: %d ", mem->rank);
	if (mem->validation_bits & CPER_MEM_VALID_BANK)
		n += snprintf(msg + n, len - n, "bank: %d ", mem->bank);
	if (mem->validation_bits & CPER_MEM_VALID_DEVICE)
		n += snprintf(msg + n, len - n, "device: %d ", mem->device);
	if (mem->validation_bits & CPER_MEM_VALID_ROW)
		n += snprintf(msg + n, len - n, "row: %d ", mem->row);
	if (mem->validation_bits & CPER_MEM_VALID_COLUMN)
		n += snprintf(msg + n, len - n, "column: %d ", mem->column);
	if (mem->validation_bits & CPER_MEM_VALID_BIT_POSITION)
		n += snprintf(msg + n, len - n, "bit_position: %d ",
			       mem->bit_pos);
	if (mem->validation_bits & CPER_MEM_VALID_REQUESTOR_ID)
		n += snprintf(msg + n, len - n, "requestor_id: 0x%016lx ",
			       mem->requestor_id);
	if (mem->validation_bits & CPER_MEM_VALID_RESPONDER_ID)
		n += snprintf(msg + n, len - n, "responder_id: 0x%016lx ",
			       mem->responder_id);
	if (mem->validation_bits & CPER_MEM_VALID_TARGET_ID)
		snprintf(msg + n, len - n, "target_id: 0x%016lx ",
			  mem->target_id);

	msg[n] = '\0';
	return n;
}

static void dmi_memdev_name(u16 handle, const char **bank, const char **device)
{
	/* emulate the info for now... */
	*bank = "unknown";
	*device = "unknown";
}

static int cper_dimm_err_location(struct cper_mem_err_compact *mem, char *msg)
{
	u32 len, n;
	const char *bank = NULL, *device = NULL;

	if (!msg || !(mem->validation_bits & CPER_MEM_VALID_MODULE_HANDLE))
		return 0;

	n = 0;
	len = CPER_REC_LEN - 1;
	dmi_memdev_name(mem->mem_dev_handle, &bank, &device);
	if (bank && device)
		n = snprintf(msg, len, "DIMM location: %s %s ", bank, device);
	else
		n = snprintf(msg, len,
			     "DIMM location: not present. DMI handle: 0x%.4x ",
			     mem->mem_dev_handle);

	msg[n] = '\0';
	return n;
}

void cper_mem_err_pack(const struct cper_sec_mem_err *mem,
		       struct cper_mem_err_compact *cmem)
{
	cmem->validation_bits = mem->validation_bits;
	cmem->node = mem->node;
	cmem->card = mem->card;
	cmem->module = mem->module;
	cmem->bank = mem->bank;
	cmem->device = mem->device;
	cmem->row = mem->row;
	cmem->column = mem->column;
	cmem->bit_pos = mem->bit_pos;
	cmem->requestor_id = mem->requestor_id;
	cmem->responder_id = mem->responder_id;
	cmem->target_id = mem->target_id;
	cmem->rank = mem->rank;
	cmem->mem_array_handle = mem->mem_array_handle;
	cmem->mem_dev_handle = mem->mem_dev_handle;
}

/*
const char *cper_mem_err_unpack(struct trace_seq *p,
				struct cper_mem_err_compact *cmem)
{
	const char *ret = trace_seq_buffer_ptr(p);

	if (cper_mem_err_location(cmem, rcd_decode_str))
		trace_seq_printf(p, "%s", rcd_decode_str);
	if (cper_dimm_err_location(cmem, rcd_decode_str))
		trace_seq_printf(p, "%s", rcd_decode_str);
	trace_seq_putc(p, '\0');

	return ret;
}
*/

static void cper_print_mem(const char *pfx, const struct cper_sec_mem_err *mem,
	int len)
{
	struct cper_mem_err_compact cmem;

	/* Don't trust UEFI 2.1/2.2 structure with bad validation bits */
	if (len == sizeof(struct cper_sec_mem_err_old) &&
	    (mem->validation_bits & ~(CPER_MEM_VALID_RANK_NUMBER - 1))) {
		printf("! valid bits set for fields beyond structure\n");
		return;
	}
	if (mem->validation_bits & CPER_MEM_VALID_ERROR_STATUS)
		printf("%s""error_status: 0x%016lx\n", pfx, mem->error_status);
	if (mem->validation_bits & CPER_MEM_VALID_PA)
		printf("%s""physical_address: 0x%016lx\n",
		       pfx, mem->physical_addr);
	if (mem->validation_bits & CPER_MEM_VALID_PA_MASK)
		printf("%s""physical_address_mask: 0x%016lx\n",
		       pfx, mem->physical_addr_mask);
	cper_mem_err_pack(mem, &cmem);
	if (cper_mem_err_location(&cmem, rcd_decode_str))
		printf("%s%s\n", pfx, rcd_decode_str);
	if (mem->validation_bits & CPER_MEM_VALID_ERROR_TYPE) {
		u8 etype = mem->error_type;
		printf("%s""error_type: %d, %s\n", pfx, etype,
		       cper_mem_err_type_str(etype));
	}
	if (cper_dimm_err_location(&cmem, rcd_decode_str))
		printf("%s%s\n", pfx, rcd_decode_str);
}

static const char * const pcie_port_type_strs[] = {
	"PCIe end point",
	"legacy PCI end point",
	"unknown",
	"unknown",
	"root port",
	"upstream switch port",
	"downstream switch port",
	"PCIe to PCI/PCI-X bridge",
	"PCI/PCI-X to PCIe bridge",
	"root complex integrated endpoint device",
	"root complex event collector",
};

static void cper_print_pcie(const char *pfx, const struct cper_sec_pcie *pcie,
			    const struct acpi_hest_generic_data *gdata)
{
	if (pcie->validation_bits & CPER_PCIE_VALID_PORT_TYPE)
		printf("%s""port_type: %d, %s\n", pfx, pcie->port_type,
		       pcie->port_type < ARRAY_SIZE(pcie_port_type_strs) ?
		       pcie_port_type_strs[pcie->port_type] : "unknown");
	if (pcie->validation_bits & CPER_PCIE_VALID_VERSION)
		printf("%s""version: %d.%d\n", pfx,
		       pcie->version.major, pcie->version.minor);
	if (pcie->validation_bits & CPER_PCIE_VALID_COMMAND_STATUS)
		printf("%s""command: 0x%04x, status: 0x%04x\n", pfx,
		       pcie->command, pcie->status);
	if (pcie->validation_bits & CPER_PCIE_VALID_DEVICE_ID) {
		const __u8 *p;
		printf("%s""device_id: %04x:%02x:%02x.%x\n", pfx,
		       pcie->device_id.segment, pcie->device_id.bus,
		       pcie->device_id.device, pcie->device_id.function);
		printf("%s""slot: %d\n", pfx,
		       pcie->device_id.slot >> CPER_PCIE_SLOT_SHIFT);
		printf("%s""secondary_bus: 0x%02x\n", pfx,
		       pcie->device_id.secondary_bus);
		printf("%s""vendor_id: 0x%04x, device_id: 0x%04x\n", pfx,
		       pcie->device_id.vendor_id, pcie->device_id.device_id);
		p = pcie->device_id.class_code;
		printf("%s""class_code: %02x%02x%02x\n", pfx, p[0], p[1], p[2]);
	}
	if (pcie->validation_bits & CPER_PCIE_VALID_SERIAL_NUMBER)
		printf("%s""serial number: 0x%04x, 0x%04x\n", pfx,
		       pcie->serial_number.lower, pcie->serial_number.upper);
	if (pcie->validation_bits & CPER_PCIE_VALID_BRIDGE_CONTROL_STATUS)
		printf(
	"%s""bridge: secondary_status: 0x%04x, control: 0x%04x\n",
	pfx, pcie->bridge.secondary_status, pcie->bridge.control);
}

/*
static inline void *acpi_hest_generic_data_payload(struct acpi_hest_generic_data *gdata)
{
	return acpi_hest_generic_data_version(gdata) >= 3 ?
		(void *)(((struct acpi_hest_generic_data_v300 *)(gdata)) + 1) :
		gdata + 1;
}
*/

static void cper_estatus_print_section(
	const char *pfx, struct acpi_hest_generic_data *gdata, int sec_no)
{
	uuid_le *sec_type = (uuid_le *)gdata->section_type;
	__u16 severity;
	char newpfx[64];

	severity = gdata->error_severity;
	printf("%s""Error %d, type: %s\n", pfx, sec_no,
	       cper_severity_str(severity));
	if (gdata->validation_bits & CPER_SEC_VALID_FRU_ID)
		printf("%s""fru_id: %pUl\n", pfx, (uuid_le *)gdata->fru_id);
	if (gdata->validation_bits & CPER_SEC_VALID_FRU_TEXT)
		printf("%s""fru_text: %.20s\n", pfx, gdata->fru_text);

	snprintf(newpfx, sizeof(newpfx), "%s%s", pfx, INDENT_SP);
	if (!uuid_le_cmp(*sec_type, CPER_SEC_PROC_GENERIC)) {
		struct cper_sec_proc_generic *proc_err;

		proc_err = acpi_hest_generic_data_payload(gdata);
		printf("%s""section_type: general processor error\n", newpfx);
		if (gdata->error_data_length >= sizeof(*proc_err))
			cper_print_proc_generic(newpfx, proc_err);
		else
			goto err_section_too_small;
	} else if (!uuid_le_cmp(*sec_type, CPER_SEC_PLATFORM_MEM)) {
		struct cper_sec_mem_err *mem_err;

		mem_err = acpi_hest_generic_data_payload(gdata);
		printf("%s""section_type: memory error\n", newpfx);
		if (gdata->error_data_length >=
		    sizeof(struct cper_sec_mem_err_old))
			cper_print_mem(newpfx, mem_err,
				       gdata->error_data_length);
		else
			goto err_section_too_small;
	} else if (!uuid_le_cmp(*sec_type, CPER_SEC_PCIE)) {
		struct cper_sec_pcie *pcie;

		pcie = acpi_hest_generic_data_payload(gdata);
		printf("%s""section_type: PCIe error\n", newpfx);
		if (gdata->error_data_length >= sizeof(*pcie))
			cper_print_pcie(newpfx, pcie, gdata);
		else
			goto err_section_too_small;
	} else if (!uuid_le_cmp(*sec_type, CPER_SEC_PROC_ARMV8)) {
		struct cper_sec_proc_armv8 *armv8_err;

		armv8_err = acpi_hest_generic_data_payload(gdata);
		printf("%ssection_type: ARMv8 processor error\n", newpfx);
		if (gdata->error_data_length >= sizeof(*armv8_err))
			cper_print_proc_armv8(newpfx, armv8_err);
		else
			goto err_section_too_small;
	} else {
		const void *unknown_err;

		unknown_err = acpi_hest_generic_data_payload(gdata);
		printf("%ssection type: %pUl\n", newpfx, sec_type);
		printf("%ssection length: %d\n", newpfx,
		       gdata->error_data_length);
		print_hex_dump(newpfx, DUMP_PREFIX_OFFSET, 16, 4,
			       unknown_err, gdata->error_data_length, 0);
	}

	return;

err_section_too_small:
	printf("! error section length is too small\n");
}

static void cper_estatus_print_section_v300(const char *pfx,
	const struct acpi_hest_generic_data_v300 *gdata, int sec_no)
{
	__u8 hour, min, sec, day, mon, year, century, *timestamp;

	if (gdata->validation_bits & ACPI_HEST_GEN_VALID_TIMESTAMP) {
		timestamp = (__u8 *)&(gdata->time_stamp);
		memcpy(&sec, timestamp, 1);
		memcpy(&min, timestamp + 1, 1);
		memcpy(&hour, timestamp + 2, 1);
		memcpy(&day, timestamp + 4, 1);
		memcpy(&mon, timestamp + 5, 1);
		memcpy(&year, timestamp + 6, 1);
		memcpy(&century, timestamp + 7, 1);
		printf("%stime: ", pfx);
		printf("%7s", 0x01 & *(timestamp + 3) ? "precise" : "");
		printf(" %02d:%02d:%02d %02d%02d-%02d-%02d\n",
			bcd2bin(hour), bcd2bin(min), bcd2bin(sec),
			bcd2bin(century), bcd2bin(year), bcd2bin(mon),
			bcd2bin(day));
	}

	cper_estatus_print_section(pfx,
				   (struct acpi_hest_generic_data *)gdata,
				   sec_no);
}

void cper_estatus_print(const char *pfx,
			const struct acpi_hest_generic_status *estatus)
{
	struct acpi_hest_generic_data *gdata;
	struct acpi_hest_generic_data_v300 *gdata_v3 = NULL;
	unsigned int data_len, gedata_len;
	int sec_no = 0;
	char newpfx[64];
	__u16 severity;

	severity = estatus->error_severity;
	if (severity == CPER_SEV_CORRECTED)
		printf("%s%s\n", pfx,
		       "It has been corrected by h/w "
		       "and requires no further action");
	printf("%s event severity: %s\n", pfx, cper_severity_str(severity));
	data_len = estatus->data_length;
	gdata = (struct acpi_hest_generic_data *)(estatus + 1);
	if ((gdata->revision >> 8) >= 0x03)
		gdata_v3 = (struct acpi_hest_generic_data_v300 *)gdata;

	snprintf(newpfx, sizeof(newpfx), "%s%s", pfx, INDENT_SP);

	if (gdata_v3) {
		while (data_len >= sizeof(*gdata_v3)) {
			gedata_len = gdata_v3->error_data_length;
			cper_estatus_print_section_v300(newpfx, gdata_v3,
							sec_no);
			data_len -= gedata_len + sizeof(*gdata_v3);
			gdata_v3 = (void *)(gdata_v3 + 1) + gedata_len;
			sec_no++;
		}
	} else {
		while (data_len >= sizeof(*gdata)) {
			gedata_len = gdata->error_data_length;
			cper_estatus_print_section(newpfx, gdata, sec_no);
			data_len -= gedata_len + sizeof(*gdata);
			gdata = (void *)(gdata + 1) + gedata_len;
			sec_no++;
		}
	}
}

int cper_estatus_check_header(const struct acpi_hest_generic_status *estatus)
{
	if (estatus->data_length &&
	    estatus->data_length < sizeof(struct acpi_hest_generic_data))
		return -EINVAL;
	if (estatus->raw_data_length &&
	    estatus->raw_data_offset < sizeof(*estatus) + estatus->data_length)
		return -EINVAL;

	return 0;
}

int cper_estatus_check(const struct acpi_hest_generic_status *estatus)
{
	struct acpi_hest_generic_data *gdata;
	struct acpi_hest_generic_data_v300 *gdata_v3 = NULL;
	unsigned int data_len, gedata_len;
	int rc;

	rc = cper_estatus_check_header(estatus);
	if (rc)
		return rc;
	data_len = estatus->data_length;
	gdata = (struct acpi_hest_generic_data *)(estatus + 1);

	if ((gdata->revision >> 8) >= 0x03) {
		gdata_v3 = (struct acpi_hest_generic_data_v300 *)gdata;
		while (data_len >= sizeof(*gdata_v3)) {
			gedata_len = gdata_v3->error_data_length;
			if (gedata_len > data_len - sizeof(*gdata_v3))
				return -EINVAL;
			data_len -= gedata_len + sizeof(*gdata_v3);
			gdata_v3 = (void *)(gdata_v3 + 1) + gedata_len;
		}
		if (data_len)
			return -EINVAL;
	} else {
		while (data_len >= sizeof(*gdata)) {
			gedata_len = gdata->error_data_length;
			if (gedata_len > data_len - sizeof(*gdata))
				return -EINVAL;
			data_len -= gedata_len + sizeof(*gdata);
			gdata = (void *)(gdata + 1) + gedata_len;
		}
		if (data_len)
			return -EINVAL;
	}

	return 0;
}

u32 cper_estatus_len(struct acpi_hest_generic_status *estatus)
{
	if (estatus->raw_data_length)
		return estatus->raw_data_offset + \
			estatus->raw_data_length;
	else
		return sizeof(*estatus) + estatus->data_length;
}
