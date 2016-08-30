
#include "esb.h"

#include <stdio.h>
#include <time.h>


#define SET_ERR_COUNT(x)	((x & 0xff)<<4)
#define GET_ERR_COUNT(x)	((x>>4) & 0xff)
#define CLEAR_ERR_COUNT(x)	((x) & 0xff)

int build_generic_status(struct acpi_hest_generic_status *s)
{
	int ret = 1;

	memset(s, 0, sizeof(*s));

	/* initial status, assuming we add more later */
	s->block_status = 0;
	s->block_status |= SET_ERR_COUNT(0);	/* 0 until we add generics */
	s->raw_data_offset = sizeof(*s);
	s->raw_data_length = 0;
	s->data_length = 0;
	s->error_severity = ACPI_HEST_GEN_ERROR_NONE;

	return ret;
}

static void set_fru_id(unsigned char *id)
{
	/* id is fixed at 16 bytes */
	const int ID_LEN = 16;
	static int next_id = 0;
	char buf[ID_LEN];

	memset(buf, 0, ID_LEN);
	snprintf(buf, ID_LEN, "FRU ID %04d", next_id++);
	printf("BUF: %s\n", buf);
	memcpy(id, buf, ID_LEN);
}

static void set_fru_text(unsigned char *text)
{
	/* text is fixed at 20 bytes */
	const int TEXT_LEN = 20;
	static int next_text = 0;
	char buf[TEXT_LEN];

	memset(buf, 0, TEXT_LEN);
	snprintf(buf, TEXT_LEN, "FRU TEXT %04d", next_text++);
	memcpy(text, buf, TEXT_LEN);
}

static unsigned char bin2bcd(unsigned char val)
{
	return ((((val) / 10) << 4) + (val) % 10);
}

static void set_time_stamp(u64 *ts)
{
	u8 *timestamp = (u8 *)ts;
	time_t now;
	struct tm tnow;

	now = time(NULL);
	gmtime_r(&now, &tnow);

	timestamp[0] = bin2bcd(tnow.tm_sec);
	timestamp[1] = bin2bcd(tnow.tm_min);
	timestamp[2] = bin2bcd(tnow.tm_hour);
	timestamp[4] = bin2bcd(tnow.tm_mday);
	timestamp[5] = bin2bcd(tnow.tm_mon);
	timestamp[6] = bin2bcd(tnow.tm_year);
	timestamp[7] = bin2bcd(19 + (tnow.tm_year / 100));

	timestamp[3] = 0x01;	/* claim to be precise, for now */
}

int build_generic_data(struct esb_geninfo *entry)
{
	int ret = 1;
	struct acpi_hest_generic_data_v300 *d =
		(struct acpi_hest_generic_data_v300 *)entry->gendata;

	memset(d, 0, sizeof(*d));

	/* set section type */
	memcpy(&d->section_type, &entry->stype->guid, sizeof(d->section_type));

	/* set error severity */
	if (entry->severity >= 0 && entry->severity <= 3)
		d->error_severity = entry->severity;
	else
		d->error_severity = 3;		/* no error */

	/* set revision */
	if (entry->use_v300) {
		d->revision = 0x300;
		entry->actual_size = sizeof(struct acpi_hest_generic_data_v300);
	} else {
		d->revision = 0x200;
		entry->actual_size = sizeof(struct acpi_hest_generic_data);
	}

	/* set validation bits */
	d->validation_bits = CPER_SEC_VALID_FRU_ID |
			     CPER_SEC_VALID_FRU_TEXT |
			     CPER_SEC_VALID_TIME_STAMP;

	/* set flags */
	d->flags = entry->flags;

	/* set error data length */
	d->error_data_length = 0;	/* zero until we add CPER records */

	/* set FRU ID */
	set_fru_id(d->fru_id);

	/* set FRU text */
	set_fru_text(d->fru_text);

	/* set time stamp */
	if (entry->use_v300)
		set_time_stamp(&d->time_stamp);

	return ret;
}

void add_generic_data(unsigned char *cur_esb, struct esb_geninfo *info)
{
	struct acpi_hest_generic_status *esb =
		(struct acpi_hest_generic_status *)cur_esb;
	u8 count;

	count = GET_ERR_COUNT(esb->block_status);
	count++;
	esb->block_status = CLEAR_ERR_COUNT(esb->block_status);
	esb->block_status |= SET_ERR_COUNT(count);
	esb->data_length += info->actual_size;
	esb->error_severity = ACPI_HEST_GEN_ERROR_FATAL;
}
