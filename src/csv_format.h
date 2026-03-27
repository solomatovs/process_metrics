/*
 * csv_format.h — fast CSV formatting without snprintf
 *
 * All functions write directly into a char buffer using memcpy/manual
 * conversion, avoiding the overhead of printf-family format string parsing.
 *
 * csv_format_row() replaces the former snprintf-based format_csv_row()
 * and is ~5–8× faster for the same output.
 */

#ifndef CSV_FORMAT_H
#define CSV_FORMAT_H

#include "event_file.h"

/*
 * Returns pointer to CSV_HEADER string (static, null-terminated).
 * Length is written to *len if len is not NULL.
 */
const char *csv_header(int *len);

/*
 * Format one ef_record as a CSV row into buf[0..buflen-1].
 *
 * resolve_cgroup: callback to resolve cgroup path (e.g. docker name).
 *                 May be NULL — raw cgroup is used as-is.
 *
 * Returns number of bytes written (excluding NUL), or -1 if buf is too small.
 */
int csv_format_row(char *buf, int buflen,
		   const struct ef_record *rec,
		   void (*resolve_cgroup)(const char *raw, char *out, int outlen));

#endif /* CSV_FORMAT_H */
