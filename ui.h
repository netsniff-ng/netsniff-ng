#ifndef UI_H
#define UI_H

#include <stdbool.h>
#include <inttypes.h>

#include "list.h"

enum ui_event_id {
	UI_EVT_SCROLL_LEFT,
	UI_EVT_SCROLL_RIGHT,
};

enum ui_align {
	UI_ALIGN_LEFT,
	UI_ALIGN_RIGHT,
};

struct ui_text {
	chtype *str;
	size_t slen;
	size_t len;
};

struct ui_col {
	struct list_head entry;
	uint32_t id;
	char *name;
	uint32_t len;
	int pos;
	int color;
	enum ui_align align;
};

struct ui_table {
	int y;
	int x;
	int rows_y;
	struct list_head cols;
	struct ui_text *row;
	int hdr_color;
	int col_pad;
	int width;
	int height;
	int scroll_x;
};

extern void ui_table_init(struct ui_table *tbl);
extern void ui_table_uninit(struct ui_table *tbl);
extern void ui_table_clear(struct ui_table *tbl);
extern void ui_table_pos_set(struct ui_table *tbl, int y, int x);
extern void ui_table_height_set(struct ui_table *tbl, int height);

extern void ui_table_col_add(struct ui_table *tbl, uint32_t id, char *name,
			     uint32_t len);
extern void ui_table_col_color_set(struct ui_table *tbl, int col_id, int color);
extern void ui_table_col_align_set(struct ui_table *tbl, int col_id, enum ui_align align);

extern void ui_table_row_add(struct ui_table *tbl);
extern void ui_table_row_show(struct ui_table *tbl);
extern void ui_table_row_col_set(struct ui_table *tbl, uint32_t col_id,
				 const char *str);

extern void ui_table_header_color_set(struct ui_table *tbl, int color);
extern void ui_table_header_print(struct ui_table *tbl);

extern void ui_table_event_send(struct ui_table *tbl, enum ui_event_id id);

#endif /* UI_H */
