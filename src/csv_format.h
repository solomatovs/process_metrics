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
 * Resolver callbacks used during CSV formatting.
 * Any field may be NULL — raw values are used as-is.
 */
struct csv_resolvers {
	void (*resolve_cgroup)(const char *raw, char *out, int outlen);
	void (*resolve_uid)(__u32 uid, char *out, int outlen);
};

/*
 * Format one ef_record as a CSV row into buf[0..buflen-1].
 *
 * resolvers: optional callbacks for lazy resolution (cgroup, uid).
 *            May be NULL — raw values are used as-is.
 *
 * Returns number of bytes written (excluding NUL), or -1 if buf is too small.
 */
int csv_format_row(char *buf, int buflen,
		   const struct ef_record *rec,
		   const struct csv_resolvers *resolvers);

#endif /* CSV_FORMAT_H */
