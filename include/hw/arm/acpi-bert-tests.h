#ifndef ACPI_BERT_TESTS_H
#define ACPI_BERT_TESTS_H

#include "qemu/osdep.h"

#ifdef CONFIG_BERT_TESTS
extern void build_acpi_bert_tests(void);
#else
void build_acpi_bert_tests(void) { return; }
#endif

#endif	/* ACPI_BERT_TESTS_H */
