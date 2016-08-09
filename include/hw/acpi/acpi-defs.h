/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef QEMU_ACPI_DEFS_H
#define QEMU_ACPI_DEFS_H

enum {
    ACPI_FADT_F_WBINVD,
    ACPI_FADT_F_WBINVD_FLUSH,
    ACPI_FADT_F_PROC_C1,
    ACPI_FADT_F_P_LVL2_UP,
    ACPI_FADT_F_PWR_BUTTON,
    ACPI_FADT_F_SLP_BUTTON,
    ACPI_FADT_F_FIX_RTC,
    ACPI_FADT_F_RTC_S4,
    ACPI_FADT_F_TMR_VAL_EXT,
    ACPI_FADT_F_DCK_CAP,
    ACPI_FADT_F_RESET_REG_SUP,
    ACPI_FADT_F_SEALED_CASE,
    ACPI_FADT_F_HEADLESS,
    ACPI_FADT_F_CPU_SW_SLP,
    ACPI_FADT_F_PCI_EXP_WAK,
    ACPI_FADT_F_USE_PLATFORM_CLOCK,
    ACPI_FADT_F_S4_RTC_STS_VALID,
    ACPI_FADT_F_REMOTE_POWER_ON_CAPABLE,
    ACPI_FADT_F_FORCE_APIC_CLUSTER_MODEL,
    ACPI_FADT_F_FORCE_APIC_PHYSICAL_DESTINATION_MODE,
    ACPI_FADT_F_HW_REDUCED_ACPI,
    ACPI_FADT_F_LOW_POWER_S0_IDLE_CAPABLE,
};

/*
 * ACPI 2.0 Generic Address Space definition.
 */
struct Acpi20GenericAddress {
    uint8_t  address_space_id;
    uint8_t  register_bit_width;
    uint8_t  register_bit_offset;
    uint8_t  reserved;
    uint64_t address;
} QEMU_PACKED;
typedef struct Acpi20GenericAddress Acpi20GenericAddress;

struct AcpiRsdpDescriptor {        /* Root System Descriptor Pointer */
    uint64_t signature;              /* ACPI signature, contains "RSD PTR " */
    uint8_t  checksum;               /* To make sum of struct == 0 */
    uint8_t  oem_id [6];             /* OEM identification */
    uint8_t  revision;               /* Must be 0 for 1.0, 2 for 2.0 */
    uint32_t rsdt_physical_address;  /* 32-bit physical address of RSDT */
    uint32_t length;                 /* XSDT Length in bytes including hdr */
    uint64_t xsdt_physical_address;  /* 64-bit physical address of XSDT */
    uint8_t  extended_checksum;      /* Checksum of entire table */
    uint8_t  reserved [3];           /* Reserved field must be 0 */
} QEMU_PACKED;
typedef struct AcpiRsdpDescriptor AcpiRsdpDescriptor;

/* Table structure from Linux kernel (the ACPI tables are under the
   BSD license) */


#define ACPI_TABLE_HEADER_DEF   /* ACPI common table header */ \
    uint32_t signature;          /* ACPI signature (4 ASCII characters) */ \
    uint32_t length;                 /* Length of table, in bytes, including header */ \
    uint8_t  revision;               /* ACPI Specification minor version # */ \
    uint8_t  checksum;               /* To make sum of entire table == 0 */ \
    uint8_t  oem_id [6];             /* OEM identification */ \
    uint8_t  oem_table_id [8];       /* OEM table identification */ \
    uint32_t oem_revision;           /* OEM revision number */ \
    uint8_t  asl_compiler_id [4];    /* ASL compiler vendor ID */ \
    uint32_t asl_compiler_revision;  /* ASL compiler revision number */


struct AcpiTableHeader         /* ACPI common table header */
{
    ACPI_TABLE_HEADER_DEF
} QEMU_PACKED;
typedef struct AcpiTableHeader AcpiTableHeader;

/*
 * ACPI Fixed ACPI Description Table (FADT)
 */
#define ACPI_FADT_COMMON_DEF /* FADT common definition */ \
    ACPI_TABLE_HEADER_DEF    /* ACPI common table header */ \
    uint32_t firmware_ctrl;  /* Physical address of FACS */ \
    uint32_t dsdt;         /* Physical address of DSDT */ \
    uint8_t  model;        /* System Interrupt Model */ \
    uint8_t  reserved1;    /* Reserved */ \
    uint16_t sci_int;      /* System vector of SCI interrupt */ \
    uint32_t smi_cmd;      /* Port address of SMI command port */ \
    uint8_t  acpi_enable;  /* Value to write to smi_cmd to enable ACPI */ \
    uint8_t  acpi_disable; /* Value to write to smi_cmd to disable ACPI */ \
    /* Value to write to SMI CMD to enter S4BIOS state */ \
    uint8_t  S4bios_req; \
    uint8_t  reserved2;    /* Reserved - must be zero */ \
    /* Port address of Power Mgt 1a acpi_event Reg Blk */ \
    uint32_t pm1a_evt_blk; \
    /* Port address of Power Mgt 1b acpi_event Reg Blk */ \
    uint32_t pm1b_evt_blk; \
    uint32_t pm1a_cnt_blk; /* Port address of Power Mgt 1a Control Reg Blk */ \
    uint32_t pm1b_cnt_blk; /* Port address of Power Mgt 1b Control Reg Blk */ \
    uint32_t pm2_cnt_blk;  /* Port address of Power Mgt 2 Control Reg Blk */ \
    uint32_t pm_tmr_blk;   /* Port address of Power Mgt Timer Ctrl Reg Blk */ \
    /* Port addr of General Purpose acpi_event 0 Reg Blk */ \
    uint32_t gpe0_blk; \
    /* Port addr of General Purpose acpi_event 1 Reg Blk */ \
    uint32_t gpe1_blk; \
    uint8_t  pm1_evt_len;  /* Byte length of ports at pm1_x_evt_blk */ \
    uint8_t  pm1_cnt_len;  /* Byte length of ports at pm1_x_cnt_blk */ \
    uint8_t  pm2_cnt_len;  /* Byte Length of ports at pm2_cnt_blk */ \
    uint8_t  pm_tmr_len;   /* Byte Length of ports at pm_tm_blk */ \
    uint8_t  gpe0_blk_len; /* Byte Length of ports at gpe0_blk */ \
    uint8_t  gpe1_blk_len; /* Byte Length of ports at gpe1_blk */ \
    uint8_t  gpe1_base;    /* Offset in gpe model where gpe1 events start */ \
    uint8_t  reserved3;    /* Reserved */ \
    uint16_t plvl2_lat;    /* Worst case HW latency to enter/exit C2 state */ \
    uint16_t plvl3_lat;    /* Worst case HW latency to enter/exit C3 state */ \
    uint16_t flush_size;   /* Size of area read to flush caches */ \
    uint16_t flush_stride; /* Stride used in flushing caches */ \
    uint8_t  duty_offset;  /* Bit location of duty cycle field in p_cnt reg */ \
    uint8_t  duty_width;   /* Bit width of duty cycle field in p_cnt reg */ \
    uint8_t  day_alrm;     /* Index to day-of-month alarm in RTC CMOS RAM */ \
    uint8_t  mon_alrm;     /* Index to month-of-year alarm in RTC CMOS RAM */ \
    uint8_t  century;      /* Index to century in RTC CMOS RAM */

struct AcpiFadtDescriptorRev1
{
    ACPI_FADT_COMMON_DEF
    uint8_t  reserved4;              /* Reserved */
    uint8_t  reserved4a;             /* Reserved */
    uint8_t  reserved4b;             /* Reserved */
    uint32_t flags;
} QEMU_PACKED;
typedef struct AcpiFadtDescriptorRev1 AcpiFadtDescriptorRev1;

struct AcpiGenericAddress {
    uint8_t space_id;        /* Address space where struct or register exists */
    uint8_t bit_width;       /* Size in bits of given register */
    uint8_t bit_offset;      /* Bit offset within the register */
    uint8_t access_width;    /* Minimum Access size (ACPI 3.0) */
    uint64_t address;        /* 64-bit address of struct or register */
} QEMU_PACKED;

struct AcpiFadtDescriptorRev5_1 {
    ACPI_FADT_COMMON_DEF
    /* IA-PC Boot Architecture Flags (see below for individual flags) */
    uint16_t boot_flags;
    uint8_t reserved;    /* Reserved, must be zero */
    /* Miscellaneous flag bits (see below for individual flags) */
    uint32_t flags;
    /* 64-bit address of the Reset register */
    struct AcpiGenericAddress reset_register;
    /* Value to write to the reset_register port to reset the system */
    uint8_t reset_value;
    /* ARM-Specific Boot Flags (see below for individual flags) (ACPI 5.1) */
    uint16_t arm_boot_flags;
    uint8_t minor_revision;  /* FADT Minor Revision (ACPI 5.1) */
    uint64_t Xfacs;          /* 64-bit physical address of FACS */
    uint64_t Xdsdt;          /* 64-bit physical address of DSDT */
    /* 64-bit Extended Power Mgt 1a Event Reg Blk address */
    struct AcpiGenericAddress xpm1a_event_block;
    /* 64-bit Extended Power Mgt 1b Event Reg Blk address */
    struct AcpiGenericAddress xpm1b_event_block;
    /* 64-bit Extended Power Mgt 1a Control Reg Blk address */
    struct AcpiGenericAddress xpm1a_control_block;
    /* 64-bit Extended Power Mgt 1b Control Reg Blk address */
    struct AcpiGenericAddress xpm1b_control_block;
    /* 64-bit Extended Power Mgt 2 Control Reg Blk address */
    struct AcpiGenericAddress xpm2_control_block;
    /* 64-bit Extended Power Mgt Timer Ctrl Reg Blk address */
    struct AcpiGenericAddress xpm_timer_block;
    /* 64-bit Extended General Purpose Event 0 Reg Blk address */
    struct AcpiGenericAddress xgpe0_block;
    /* 64-bit Extended General Purpose Event 1 Reg Blk address */
    struct AcpiGenericAddress xgpe1_block;
    /* 64-bit Sleep Control register (ACPI 5.0) */
    struct AcpiGenericAddress sleep_control;
    /* 64-bit Sleep Status register (ACPI 5.0) */
    struct AcpiGenericAddress sleep_status;
} QEMU_PACKED;

typedef struct AcpiFadtDescriptorRev5_1 AcpiFadtDescriptorRev5_1;

enum {
    ACPI_FADT_ARM_USE_PSCI_G_0_2 = 0,
    ACPI_FADT_ARM_PSCI_USE_HVC = 1,
};

/*
 * Serial Port Console Redirection Table (SPCR), Rev. 1.02
 *
 * For .interface_type see Debug Port Table 2 (DBG2) serial port
 * subtypes in Table 3, Rev. May 22, 2012
 */
struct AcpiSerialPortConsoleRedirection {
    ACPI_TABLE_HEADER_DEF
    uint8_t  interface_type;
    uint8_t  reserved1[3];
    struct AcpiGenericAddress base_address;
    uint8_t  interrupt_types;
    uint8_t  irq;
    uint32_t gsi;
    uint8_t  baud;
    uint8_t  parity;
    uint8_t  stopbits;
    uint8_t  flowctrl;
    uint8_t  term_type;
    uint8_t  reserved2;
    uint16_t pci_device_id;
    uint16_t pci_vendor_id;
    uint8_t  pci_bus;
    uint8_t  pci_slot;
    uint8_t  pci_func;
    uint32_t pci_flags;
    uint8_t  pci_seg;
    uint32_t reserved3;
} QEMU_PACKED;
typedef struct AcpiSerialPortConsoleRedirection
               AcpiSerialPortConsoleRedirection;

/*
 * ACPI 1.0 Root System Description Table (RSDT)
 */
struct AcpiRsdtDescriptorRev1
{
    ACPI_TABLE_HEADER_DEF       /* ACPI common table header */
    uint32_t table_offset_entry[0];  /* Array of pointers to other */
    /* ACPI tables */
} QEMU_PACKED;
typedef struct AcpiRsdtDescriptorRev1 AcpiRsdtDescriptorRev1;

/*
 * ACPI 1.0 Firmware ACPI Control Structure (FACS)
 */
struct AcpiFacsDescriptorRev1
{
    uint32_t signature;           /* ACPI Signature */
    uint32_t length;                 /* Length of structure, in bytes */
    uint32_t hardware_signature;     /* Hardware configuration signature */
    uint32_t firmware_waking_vector; /* ACPI OS waking vector */
    uint32_t global_lock;            /* Global Lock */
    uint32_t flags;
    uint8_t  resverved3 [40];        /* Reserved - must be zero */
} QEMU_PACKED;
typedef struct AcpiFacsDescriptorRev1 AcpiFacsDescriptorRev1;

/*
 * Differentiated System Description Table (DSDT)
 */

/*
 * MADT values and structures
 */

/* Values for MADT PCATCompat */

#define ACPI_DUAL_PIC                0
#define ACPI_MULTIPLE_APIC           1

/* Master MADT */

struct AcpiMultipleApicTable
{
    ACPI_TABLE_HEADER_DEF     /* ACPI common table header */
    uint32_t local_apic_address;     /* Physical address of local APIC */
    uint32_t flags;
} QEMU_PACKED;
typedef struct AcpiMultipleApicTable AcpiMultipleApicTable;

/* Values for Type in APIC sub-headers */

#define ACPI_APIC_PROCESSOR          0
#define ACPI_APIC_IO                 1
#define ACPI_APIC_XRUPT_OVERRIDE     2
#define ACPI_APIC_NMI                3
#define ACPI_APIC_LOCAL_NMI          4
#define ACPI_APIC_ADDRESS_OVERRIDE   5
#define ACPI_APIC_IO_SAPIC           6
#define ACPI_APIC_LOCAL_SAPIC        7
#define ACPI_APIC_XRUPT_SOURCE       8
#define ACPI_APIC_LOCAL_X2APIC       9
#define ACPI_APIC_LOCAL_X2APIC_NMI      10
#define ACPI_APIC_GENERIC_INTERRUPT     11
#define ACPI_APIC_GENERIC_DISTRIBUTOR   12
#define ACPI_APIC_GENERIC_MSI_FRAME     13
#define ACPI_APIC_GENERIC_REDISTRIBUTOR 14
#define ACPI_APIC_RESERVED              15   /* 15 and greater are reserved */

/*
 * MADT sub-structures (Follow MULTIPLE_APIC_DESCRIPTION_TABLE)
 */
#define ACPI_SUB_HEADER_DEF   /* Common ACPI sub-structure header */\
    uint8_t  type;                               \
    uint8_t  length;

/* Sub-structures for MADT */

struct AcpiMadtProcessorApic
{
    ACPI_SUB_HEADER_DEF
    uint8_t  processor_id;           /* ACPI processor id */
    uint8_t  local_apic_id;          /* Processor's local APIC id */
    uint32_t flags;
} QEMU_PACKED;
typedef struct AcpiMadtProcessorApic AcpiMadtProcessorApic;

struct AcpiMadtIoApic
{
    ACPI_SUB_HEADER_DEF
    uint8_t  io_apic_id;             /* I/O APIC ID */
    uint8_t  reserved;               /* Reserved - must be zero */
    uint32_t address;                /* APIC physical address */
    uint32_t interrupt;              /* Global system interrupt where INTI
                                 * lines start */
} QEMU_PACKED;
typedef struct AcpiMadtIoApic AcpiMadtIoApic;

struct AcpiMadtIntsrcovr {
    ACPI_SUB_HEADER_DEF
    uint8_t  bus;
    uint8_t  source;
    uint32_t gsi;
    uint16_t flags;
} QEMU_PACKED;
typedef struct AcpiMadtIntsrcovr AcpiMadtIntsrcovr;

struct AcpiMadtLocalNmi {
    ACPI_SUB_HEADER_DEF
    uint8_t  processor_id;           /* ACPI processor id */
    uint16_t flags;                  /* MPS INTI flags */
    uint8_t  lint;                   /* Local APIC LINT# */
} QEMU_PACKED;
typedef struct AcpiMadtLocalNmi AcpiMadtLocalNmi;

struct AcpiMadtGenericInterrupt {
    ACPI_SUB_HEADER_DEF
    uint16_t reserved;
    uint32_t cpu_interface_number;
    uint32_t uid;
    uint32_t flags;
    uint32_t parking_version;
    uint32_t performance_interrupt;
    uint64_t parked_address;
    uint64_t base_address;
    uint64_t gicv_base_address;
    uint64_t gich_base_address;
    uint32_t vgic_interrupt;
    uint64_t gicr_base_address;
    uint64_t arm_mpidr;
} QEMU_PACKED;

typedef struct AcpiMadtGenericInterrupt AcpiMadtGenericInterrupt;

struct AcpiMadtGenericDistributor {
    ACPI_SUB_HEADER_DEF
    uint16_t reserved;
    uint32_t gic_id;
    uint64_t base_address;
    uint32_t global_irq_base;
    /* ACPI 5.1 Errata 1228 Present GIC version in MADT table */
    uint8_t version;
    uint8_t reserved2[3];
} QEMU_PACKED;

typedef struct AcpiMadtGenericDistributor AcpiMadtGenericDistributor;

struct AcpiMadtGenericMsiFrame {
    ACPI_SUB_HEADER_DEF
    uint16_t reserved;
    uint32_t gic_msi_frame_id;
    uint64_t base_address;
    uint32_t flags;
    uint16_t spi_count;
    uint16_t spi_base;
} QEMU_PACKED;

typedef struct AcpiMadtGenericMsiFrame AcpiMadtGenericMsiFrame;

struct AcpiMadtGenericRedistributor {
    ACPI_SUB_HEADER_DEF
    uint16_t reserved;
    uint64_t base_address;
    uint32_t range_length;
} QEMU_PACKED;

typedef struct AcpiMadtGenericRedistributor AcpiMadtGenericRedistributor;

/*
 * Generic Timer Description Table (GTDT)
 */

#define ACPI_GTDT_INTERRUPT_MODE        (1 << 0)
#define ACPI_GTDT_INTERRUPT_POLARITY    (1 << 1)
#define ACPI_GTDT_ALWAYS_ON             (1 << 2)

/* Triggering */

#define ACPI_LEVEL_SENSITIVE            ((uint8_t) 0x00)
#define ACPI_EDGE_SENSITIVE             ((uint8_t) 0x01)

/* Polarity */

#define ACPI_ACTIVE_HIGH                ((uint8_t) 0x00)
#define ACPI_ACTIVE_LOW                 ((uint8_t) 0x01)
#define ACPI_ACTIVE_BOTH                ((uint8_t) 0x02)

struct AcpiGenericTimerTable {
    ACPI_TABLE_HEADER_DEF
    uint64_t counter_block_addresss;
    uint32_t reserved;
    uint32_t secure_el1_interrupt;
    uint32_t secure_el1_flags;
    uint32_t non_secure_el1_interrupt;
    uint32_t non_secure_el1_flags;
    uint32_t virtual_timer_interrupt;
    uint32_t virtual_timer_flags;
    uint32_t non_secure_el2_interrupt;
    uint32_t non_secure_el2_flags;
    uint64_t counter_read_block_address;
    uint32_t platform_timer_count;
    uint32_t platform_timer_offset;
} QEMU_PACKED;
typedef struct AcpiGenericTimerTable AcpiGenericTimerTable;

/*
 * HPET Description Table
 */
struct Acpi20Hpet {
    ACPI_TABLE_HEADER_DEF                    /* ACPI common table header */
    uint32_t           timer_block_id;
    Acpi20GenericAddress addr;
    uint8_t            hpet_number;
    uint16_t           min_tick;
    uint8_t            page_protect;
} QEMU_PACKED;
typedef struct Acpi20Hpet Acpi20Hpet;

/*
 * SRAT (NUMA topology description) table
 */

struct AcpiSystemResourceAffinityTable
{
    ACPI_TABLE_HEADER_DEF
    uint32_t    reserved1;
    uint32_t    reserved2[2];
} QEMU_PACKED;
typedef struct AcpiSystemResourceAffinityTable AcpiSystemResourceAffinityTable;

#define ACPI_SRAT_PROCESSOR_APIC     0
#define ACPI_SRAT_MEMORY             1
#define ACPI_SRAT_PROCESSOR_x2APIC   2
#define ACPI_SRAT_PROCESSOR_GICC     3

struct AcpiSratProcessorAffinity
{
    ACPI_SUB_HEADER_DEF
    uint8_t     proximity_lo;
    uint8_t     local_apic_id;
    uint32_t    flags;
    uint8_t     local_sapic_eid;
    uint8_t     proximity_hi[3];
    uint32_t    reserved;
} QEMU_PACKED;
typedef struct AcpiSratProcessorAffinity AcpiSratProcessorAffinity;

struct AcpiSratMemoryAffinity
{
    ACPI_SUB_HEADER_DEF
    uint32_t    proximity;
    uint16_t    reserved1;
    uint64_t    base_addr;
    uint64_t    range_length;
    uint32_t    reserved2;
    uint32_t    flags;
    uint32_t    reserved3[2];
} QEMU_PACKED;
typedef struct AcpiSratMemoryAffinity AcpiSratMemoryAffinity;

struct AcpiSratProcessorGiccAffinity
{
    ACPI_SUB_HEADER_DEF
    uint32_t    proximity;
    uint32_t    acpi_processor_uid;
    uint32_t    flags;
    uint32_t    clock_domain;
} QEMU_PACKED;

typedef struct AcpiSratProcessorGiccAffinity AcpiSratProcessorGiccAffinity;

/* PCI fw r3.0 MCFG table. */
/* Subtable */
struct AcpiMcfgAllocation {
    uint64_t address;                /* Base address, processor-relative */
    uint16_t pci_segment;            /* PCI segment group number */
    uint8_t start_bus_number;       /* Starting PCI Bus number */
    uint8_t end_bus_number;         /* Final PCI Bus number */
    uint32_t reserved;
} QEMU_PACKED;
typedef struct AcpiMcfgAllocation AcpiMcfgAllocation;

struct AcpiTableMcfg {
    ACPI_TABLE_HEADER_DEF;
    uint8_t reserved[8];
    AcpiMcfgAllocation allocation[0];
} QEMU_PACKED;
typedef struct AcpiTableMcfg AcpiTableMcfg;

/*
 * TCPA Description Table
 *
 * Following Level 00, Rev 00.37 of specs:
 * http://www.trustedcomputinggroup.org/resources/tcg_acpi_specification
 */
struct Acpi20Tcpa {
    ACPI_TABLE_HEADER_DEF                    /* ACPI common table header */
    uint16_t platform_class;
    uint32_t log_area_minimum_length;
    uint64_t log_area_start_address;
} QEMU_PACKED;
typedef struct Acpi20Tcpa Acpi20Tcpa;

/*
 * TPM2
 *
 * Following Level 00, Rev 00.37 of specs:
 * http://www.trustedcomputinggroup.org/resources/tcg_acpi_specification
 */
struct Acpi20TPM2 {
    ACPI_TABLE_HEADER_DEF
    uint16_t platform_class;
    uint16_t reserved;
    uint64_t control_area_address;
    uint32_t start_method;
} QEMU_PACKED;
typedef struct Acpi20TPM2 Acpi20TPM2;

/* DMAR - DMA Remapping table r2.2 */
struct AcpiTableDmar {
    ACPI_TABLE_HEADER_DEF
    uint8_t host_address_width; /* Maximum DMA physical addressability */
    uint8_t flags;
    uint8_t reserved[10];
} QEMU_PACKED;
typedef struct AcpiTableDmar AcpiTableDmar;

/* Masks for Flags field above */
#define ACPI_DMAR_INTR_REMAP        1
#define ACPI_DMAR_X2APIC_OPT_OUT    (1 << 1)

/* Values for sub-structure type for DMAR */
enum {
    ACPI_DMAR_TYPE_HARDWARE_UNIT = 0,       /* DRHD */
    ACPI_DMAR_TYPE_RESERVED_MEMORY = 1,     /* RMRR */
    ACPI_DMAR_TYPE_ATSR = 2,                /* ATSR */
    ACPI_DMAR_TYPE_HARDWARE_AFFINITY = 3,   /* RHSR */
    ACPI_DMAR_TYPE_ANDD = 4,                /* ANDD */
    ACPI_DMAR_TYPE_RESERVED = 5             /* Reserved for furture use */
};

/*
 * Sub-structures for DMAR
 */

/* Device scope structure for DRHD. */
struct AcpiDmarDeviceScope {
    uint8_t entry_type;
    uint8_t length;
    uint16_t reserved;
    uint8_t enumeration_id;
    uint8_t bus;
    uint16_t path[0];           /* list of dev:func pairs */
} QEMU_PACKED;
typedef struct AcpiDmarDeviceScope AcpiDmarDeviceScope;

/* Type 0: Hardware Unit Definition */
struct AcpiDmarHardwareUnit {
    uint16_t type;
    uint16_t length;
    uint8_t flags;
    uint8_t reserved;
    uint16_t pci_segment;   /* The PCI Segment associated with this unit */
    uint64_t address;   /* Base address of remapping hardware register-set */
    AcpiDmarDeviceScope scope[0];
} QEMU_PACKED;
typedef struct AcpiDmarHardwareUnit AcpiDmarHardwareUnit;

/* Masks for Flags field above */
#define ACPI_DMAR_INCLUDE_PCI_ALL   1

/*
 * BERT - Boot Error Record Table, v1 (ACPI 4.0)
 */
struct AcpiTableBert {
    ACPI_TABLE_HEADER_DEF
    uint32_t region_length;	/* length of boot error region */
    uint64_t address;		/* physical address of the region */
} QEMU_PACKED;
typedef struct AcpiTableBert AcpiTableBert;

/* Boot error region format: what the BERT points to */
struct AcpiBertRegion {
    uint32_t block_status;	/* type of error information */
    uint32_t raw_data_offset;	/* offset to raw error data */
    uint32_t raw_data_length;
    uint32_t data_length;	/* length of generic error data */
    uint32_t error_severity;
} QEMU_PACKED;
typedef struct AcpiBertRegion AcpiBertRegion;

/* Values for block_status flags above */

#define ACPI_BERT_UNCORRECTABLE             (1)
#define ACPI_BERT_CORRECTABLE               (1<<1)
#define ACPI_BERT_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_BERT_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_BERT_ERROR_ENTRY_COUNT         (0xFF<<4)	/* 8 bits */

/* Values for error_severity above */

enum AcpiBertErrorSeverity {
	ACPI_BERT_ERROR_CORRECTABLE = 0,
	ACPI_BERT_ERROR_FATAL = 1,
	ACPI_BERT_ERROR_CORRECTED = 2,
	ACPI_BERT_ERROR_NONE = 3,
	ACPI_BERT_ERROR_RESERVED = 4	/* 4 and greater are reserved */
};

/*
 * Note: The generic error data that follows the error_severity field above
 * uses the struct AcpiHestGenericData defined under the HEST table below
 */


/*
 * HEST - Hardware Error Source Table, v1 (ACPI 4.0)
 */
struct AcpiTableHest {
    ACPI_TABLE_HEADER_DEF		/* standard ACPI table header */
    uint32_t error_source_count;
} QEMU_PACKED;
typedef struct AcpiTableHest AcpiTableHest;

/*
 * HEST subtables
 */
#define ACPI_HEST_SUB_HEADER_DEF   /* Common ACPI sub-structure header */\
    uint16_t  type;                               \
    uint16_t  source_id;

/* HEST subtable types */
enum AcpiHestTypes {
	ACPI_HEST_TYPE_IA32_CHECK = 0,
	ACPI_HEST_TYPE_IA32_CORRECTED_CHECK = 1,
	ACPI_HEST_TYPE_IA32_NMI = 2,
	ACPI_HEST_TYPE_NOT_USED3 = 3,
	ACPI_HEST_TYPE_NOT_USED4 = 4,
	ACPI_HEST_TYPE_NOT_USED5 = 5,
	ACPI_HEST_TYPE_AER_ROOT_PORT = 6,
	ACPI_HEST_TYPE_AER_ENDPOINT = 7,
	ACPI_HEST_TYPE_AER_BRIDGE = 8,
	ACPI_HEST_TYPE_GENERIC_ERROR = 9,
	ACPI_HEST_TYPE_GENERIC_ERROR_V2 = 10,
	ACPI_HEST_TYPE_RESERVED = 11	/* 11 and greater are reserved */
};

/*
 * IA32 Error Bank(s) - Follows the struct acpi_hest_ia_machine_check and
 * struct acpi_hest_ia_corrected structures.
 */
struct AcpiHestIaErrorBank {
	uint8_t bank_number;
	uint8_t clear_status_on_init;
	uint8_t status_format;
	uint8_t reserved;
	uint32_t control_register;
	uint64_t control_data;
	uint32_t status_register;
	uint32_t address_register;
	uint32_t misc_register;
} QEMU_PACKED;
typedef struct AcpiHestIaErrorBank AcpiHestIaErrorBank;

/* Common HEST sub-structure for PCI/AER structures below (6,7,8) */

struct AcpiHestAerCommon {
	uint16_t reserved1;
	uint8_t flags;
	uint8_t enabled;
	uint32_t records_to_preallocate;
	uint32_t max_sections_per_record;
	uint32_t bus;		/* Bus and Segment numbers */
	uint16_t device;
	uint16_t function;
	uint16_t device_control;
	uint16_t reserved2;
	uint32_t uncorrectable_mask;
	uint32_t uncorrectable_severity;
	uint32_t correctable_mask;
	uint32_t advanced_capabilities;
} QEMU_PACKED;
typedef struct AcpiHestAerCommon AcpiHestAerCommon;

/* Masks for HEST Flags fields */

#define ACPI_HEST_FIRMWARE_FIRST        (1)
#define ACPI_HEST_GLOBAL                (1<<1)

/*
 * Macros to access the bus/segment numbers in Bus field above:
 *  Bus number is encoded in bits 7:0
 *  Segment number is encoded in bits 23:8
 */
#define ACPI_HEST_BUS(bus)              ((bus) & 0xFF)
#define ACPI_HEST_SEGMENT(bus)          (((bus) >> 8) & 0xFFFF)

/* Hardware Error Notification */

struct AcpiHestNotify {
	uint8_t type;
	uint8_t length;
	uint16_t config_write_enable;
	uint32_t poll_interval;
	uint32_t vector;
	uint32_t polling_threshold_value;
	uint32_t polling_threshold_window;
	uint32_t error_threshold_value;
	uint32_t error_threshold_window;
} QEMU_PACKED;
typedef struct AcpiHestNotify AcpiHestNotify;

/* Values for Notify Type field above */

enum AcpiHestNotifyTypes {
	ACPI_HEST_NOTIFY_POLLED = 0,
	ACPI_HEST_NOTIFY_EXTERNAL = 1,
	ACPI_HEST_NOTIFY_LOCAL = 2,
	ACPI_HEST_NOTIFY_SCI = 3,
	ACPI_HEST_NOTIFY_NMI = 4,
	ACPI_HEST_NOTIFY_CMCI = 5,	/* ACPI 5.0 */
	ACPI_HEST_NOTIFY_MCE = 6,	/* ACPI 5.0 */
	ACPI_HEST_NOTIFY_GPIO = 7,	/* ACPI 6.0 */
	ACPI_HEST_NOTIFY_SEA = 8,	/* ACPI 6.1 */
	ACPI_HEST_NOTIFY_SEI = 9,	/* ACPI 6.1 */
	ACPI_HEST_NOTIFY_GSIV = 10,	/* ACPI 6.1 */
	ACPI_HEST_NOTIFY_RESERVED = 11	/* 11 and greater are reserved */
};

/* Values for config_write_enable bitfield above */

#define ACPI_HEST_TYPE                  (1)
#define ACPI_HEST_POLL_INTERVAL         (1<<1)
#define ACPI_HEST_POLL_THRESHOLD_VALUE  (1<<2)
#define ACPI_HEST_POLL_THRESHOLD_WINDOW (1<<3)
#define ACPI_HEST_ERR_THRESHOLD_VALUE   (1<<4)
#define ACPI_HEST_ERR_THRESHOLD_WINDOW  (1<<5)

/*
 * HEST subtables
 */

/* 0: IA32 Machine Check Exception */

struct AcpiHestIaMachineCheck {
	ACPI_HEST_SUB_HEADER_DEF
	uint16_t reserved1;
	uint8_t flags;
	uint8_t enabled;
	uint32_t records_to_preallocate;
	uint32_t max_sections_per_record;
	uint64_t global_capability_data;
	uint64_t global_control_data;
	uint8_t num_hardware_banks;
	uint8_t reserved3[7];
} QEMU_PACKED;
typedef struct AcpiHestIaMachineCheck AcpiHestIaMachineCheck;

/* 1: IA32 Corrected Machine Check */

struct AcpiHestIaCorrected {
	ACPI_HEST_SUB_HEADER_DEF
	uint16_t reserved1;
	uint8_t flags;
	uint8_t enabled;
	uint32_t records_to_preallocate;
	uint32_t max_sections_per_record;
	AcpiHestNotify notify;
	uint8_t num_hardware_banks;
	uint8_t reserved2[3];
} QEMU_PACKED;
typedef struct AcpiHestIaCorrected AcpiHestIaCorrected;

/* 2: IA32 Non-Maskable Interrupt */

struct AcpiHestIaNmi {
	ACPI_HEST_SUB_HEADER_DEF
	uint32_t reserved;
	uint32_t records_to_preallocate;
	uint32_t max_sections_per_record;
	uint32_t max_raw_data_length;
} QEMU_PACKED;
typedef struct AcpiHestIaNmi AcpiHestIaNmi;

/* 3,4,5: Not used */

/* 6: PCI Express Root Port AER */

struct AcpiHestAerRoot {
	ACPI_HEST_SUB_HEADER_DEF
	AcpiHestAerCommon aer;
	uint32_t root_error_command;
} QEMU_PACKED;
typedef struct AcpiHestAerRoot AcpiHestAerRoot;

/* 7: PCI Express AER (AER Endpoint) */

struct AcpiHestAer {
	ACPI_HEST_SUB_HEADER_DEF
	AcpiHestAerCommon aer;
} QEMU_PACKED;
typedef struct AcpiHestAer AcpiHestAer;

/* 8: PCI Express/PCI-X Bridge AER */

struct AcpiHestAerBridge {
	ACPI_HEST_SUB_HEADER_DEF
	AcpiHestAerCommon aer;
	uint32_t uncorrectable_mask2;
	uint32_t uncorrectable_severity2;
	uint32_t advanced_capabilities2;
} QEMU_PACKED;
typedef struct AcpiHestAerBridge AcpiHestAerBridge;

/* 9: Generic Hardware Error Source */

struct AcpiHestGeneric {
	ACPI_HEST_SUB_HEADER_DEF
	uint16_t related_source_id;
	uint8_t reserved;
	uint8_t enabled;
	uint32_t records_to_preallocate;
	uint32_t max_sections_per_record;
	uint32_t max_raw_data_length;
	struct AcpiGenericAddress error_status_address;
	AcpiHestNotify notify;
	uint32_t error_block_length;
} QEMU_PACKED;
typedef struct AcpiHestGeneric AcpiHestGeneric;

/* 10: Generic Hardware Error Source, version 2 */

struct AcpiHestGenericV2 {
	ACPI_HEST_SUB_HEADER_DEF
	uint16_t related_source_id;
	uint8_t reserved;
	uint8_t enabled;
	uint32_t records_to_preallocate;
	uint32_t max_sections_per_record;
	uint32_t max_raw_data_length;
	struct AcpiGenericAddress error_status_address;
	AcpiHestNotify notify;
	uint32_t error_block_length;
	struct AcpiGenericAddress read_ack_register;
	uint64_t read_ack_preserve;
	uint64_t read_ack_write;
} QEMU_PACKED;
typedef struct AcpiHestGenericV2 AcpiHestGenericV2;

/* Generic Error Status block */

struct AcpiHestGenericStatus {
	uint32_t block_status;
	uint32_t raw_data_offset;
	uint32_t raw_data_length;
	uint32_t data_length;
	uint32_t error_severity;
} QEMU_PACKED;
typedef struct AcpiHestGenericStatus AcpiHestGenericStatus;

/* Values for block_status flags above */

#define ACPI_HEST_UNCORRECTABLE             (1)
#define ACPI_HEST_CORRECTABLE               (1<<1)
#define ACPI_HEST_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_HEST_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_HEST_ERROR_ENTRY_COUNT         (0xFF<<4)	/* 8 bits, error count */

/* Generic Error Data entry */

struct AcpiHestGenericData {
	uint8_t section_type[16];
	uint32_t error_severity;
	uint16_t revision;
	uint8_t validation_bits;
	uint8_t flags;
	uint32_t error_data_length;
	uint8_t fru_id[16];
	uint8_t fru_text[20];
} QEMU_PACKED;
typedef struct AcpiHestGenericData AcpiHestGenericData;

/* Extension for revision 0x0300 */

struct AcpiHestGenericDataV300 {
	uint8_t section_type[16];
	uint32_t error_severity;
	uint16_t revision;
	uint8_t validation_bits;
	uint8_t flags;
	uint32_t error_data_length;
	uint8_t fru_id[16];
	uint8_t fru_text[20];
	uint64_t time_stamp;
} QEMU_PACKED;
typedef struct AcpiHestGenericDataV300 AcpiHestGenericDataV300;

/* Values for error_severity above */

#define ACPI_HEST_GEN_ERROR_RECOVERABLE     0
#define ACPI_HEST_GEN_ERROR_FATAL           1
#define ACPI_HEST_GEN_ERROR_CORRECTED       2
#define ACPI_HEST_GEN_ERROR_NONE            3

/* Flags for validation_bits above */

#define ACPI_HEST_GEN_VALID_FRU_ID          (1)
#define ACPI_HEST_GEN_VALID_FRU_STRING      (1<<1)
#define ACPI_HEST_GEN_VALID_TIMESTAMP       (1<<2)


/* Subtable header for WHEA tables (EINJ, ERST, WDAT) */

struct AcpiWheaHeader {
	uint8_t action;
	uint8_t instruction;
	uint8_t flags;
	uint8_t reserved;
	struct AcpiGenericAddress register_region;
	uint64_t value;	/* Value used with Read/Write register */
	uint64_t mask;	/* Bitmask required for this register instruction */
};

/*
 * ERST - Error Record Serialization Table, v1 (ACPI 4.0)
 */

struct AcpiTableErst {
	ACPI_HEST_SUB_HEADER_DEF
	uint32_t header_length;
	uint32_t reserved;
	uint32_t entries;
} QEMU_PACKED;
typedef struct AcpiTableErst AcpiTableErst;

/* ERST Serialization Entries (actions) */

struct AcpiErstEntry {
	struct AcpiWheaHeader whea_header;	/* Common header for WHEA tables */
} QEMU_PACKED;
typedef struct AcpiErstEntry AcpiErstEntry;

/* Masks for Flags field above */

#define ACPI_ERST_PRESERVE          (1)

/* Values for Action field above */

enum AcpiErstActions {
	ACPI_ERST_BEGIN_WRITE = 0,
	ACPI_ERST_BEGIN_READ = 1,
	ACPI_ERST_BEGIN_CLEAR = 2,
	ACPI_ERST_END = 3,
	ACPI_ERST_SET_RECORD_OFFSET = 4,
	ACPI_ERST_EXECUTE_OPERATION = 5,
	ACPI_ERST_CHECK_BUSY_STATUS = 6,
	ACPI_ERST_GET_COMMAND_STATUS = 7,
	ACPI_ERST_GET_RECORD_ID = 8,
	ACPI_ERST_SET_RECORD_ID = 9,
	ACPI_ERST_GET_RECORD_COUNT = 10,
	ACPI_ERST_BEGIN_DUMMY_WRIITE = 11,
	ACPI_ERST_NOT_USED = 12,
	ACPI_ERST_GET_ERROR_RANGE = 13,
	ACPI_ERST_GET_ERROR_LENGTH = 14,
	ACPI_ERST_GET_ERROR_ATTRIBUTES = 15,
	ACPI_ERST_ACTION_RESERVED = 16	/* 16 and greater are reserved */
};

/* Values for Instruction field above */

enum AcpiErstInstructions {
	ACPI_ERST_READ_REGISTER = 0,
	ACPI_ERST_READ_REGISTER_VALUE = 1,
	ACPI_ERST_WRITE_REGISTER = 2,
	ACPI_ERST_WRITE_REGISTER_VALUE = 3,
	ACPI_ERST_NOOP = 4,
	ACPI_ERST_LOAD_VAR1 = 5,
	ACPI_ERST_LOAD_VAR2 = 6,
	ACPI_ERST_STORE_VAR1 = 7,
	ACPI_ERST_ADD = 8,
	ACPI_ERST_SUBTRACT = 9,
	ACPI_ERST_ADD_VALUE = 10,
	ACPI_ERST_SUBTRACT_VALUE = 11,
	ACPI_ERST_STALL = 12,
	ACPI_ERST_STALL_WHILE_TRUE = 13,
	ACPI_ERST_SKIP_NEXT_IF_TRUE = 14,
	ACPI_ERST_GOTO = 15,
	ACPI_ERST_SET_SRC_ADDRESS_BASE = 16,
	ACPI_ERST_SET_DST_ADDRESS_BASE = 17,
	ACPI_ERST_MOVE_DATA = 18,
	ACPI_ERST_INSTRUCTION_RESERVED = 19	/* 19 and greater are reserved */
};

/* Command status return values */

enum AcpiErstCommandStatus {
	ACPI_ERST_SUCESS = 0,
	ACPI_ERST_NO_SPACE = 1,
	ACPI_ERST_NOT_AVAILABLE = 2,
	ACPI_ERST_FAILURE = 3,
	ACPI_ERST_RECORD_EMPTY = 4,
	ACPI_ERST_NOT_FOUND = 5,
	ACPI_ERST_STATUS_RESERVED = 6	/* 6 and greater are reserved */
};

/* Error Record Serialization Information */

struct AcpiErstInfo {
	uint16_t signature;		/* Should be "ER" */
	uint8_t data[48];
} QEMU_PACKED;
typedef struct AcpiErstInfo AcpiErstInfo;


#endif
