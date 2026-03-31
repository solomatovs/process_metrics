/*
 * csv_format.h — быстрое CSV-форматирование без snprintf
 *
 * Все функции пишут напрямую в char-буфер через memcpy/ручную конвертацию,
 * избегая накладных расходов на разбор форматной строки printf-семейства.
 *
 * csv_format_row() заменяет прежний format_csv_row() на основе snprintf
 * и работает в ~5–8× быстрее при том же выводе.
 */

#ifndef CSV_FORMAT_H
#define CSV_FORMAT_H

#include "event_file.h"

/*
 * Возвращает указатель на строку CSV-заголовка (статическая, с нуль-терминатором).
 * Длина записывается в *len, если len не NULL.
 */
const char *csv_header(int *len);

/*
 * Callback-функции для разрешения значений при CSV-форматировании.
 * Любое поле может быть NULL — используются исходные значения.
 */
struct csv_resolvers {
	void (*resolve_cgroup)(const char *raw, char *out, int outlen);
	void (*resolve_uid)(__u32 uid, char *out, int outlen);
};

/*
 * Форматирует одну запись ef_record как CSV-строку в buf[0..buflen-1].
 *
 * resolvers: необязательные callback-функции для отложенного разрешения (cgroup, uid).
 *            Может быть NULL — используются исходные значения.
 *
 * Возвращает количество записанных байт (без NUL) или -1, если буфер слишком мал.
 */
int csv_format_row(char *buf, int buflen, const struct ef_record *rec,
		   const struct csv_resolvers *resolvers);

#endif /* CSV_FORMAT_H */
