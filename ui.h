#ifndef UI_H
#define UI_H

#define _LGPL_SOURCE
#include <stdbool.h>
#include <inttypes.h>
#include <urcu/list.h>

enum ui_event_id {
	UI_EVT_SCROLL_LEFT,
	UI_EVT_SCROLL_RIGHT,
	UI_EVT_SCROLL_UP,
	UI_EVT_SCROLL_DOWN,
	UI_EVT_SELECT_NEXT,
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
	struct cds_list_head entry;
	uint32_t id;
	const char *name;
	uint32_t len;
	int pos;
	int color;
	enum ui_align align;
};

struct ui_table {
	int y;
	int x;
	int rows_y;
	struct cds_list_head cols;
	struct ui_text *row;
	int hdr_color;
	int col_pad;
	int width;
	int height;
	int scroll_x;
	int scroll_y;
	const char *delim;
	int data_count;

	void * (* data_iter)(void *data);
	void (* data_bind)(struct ui_table *tbl, const void *data);
};

struct ui_tab;

enum ui_tab_event_t {
	UI_TAB_EVT_OPEN,
	UI_TAB_EVT_CLOSE,
};

typedef void (* ui_tab_event_cb) (struct ui_tab *tab, enum ui_tab_event_t evt,
				  uint32_t id);

struct ui_tab {
	struct ui_col *active;
	struct ui_table tbl;
	int color;

	ui_tab_event_cb on_tab_event;
};

extern void ui_table_init(struct ui_table *tbl);
extern void ui_table_uninit(struct ui_table *tbl);
extern void ui_table_clear(struct ui_table *tbl);
extern void ui_table_pos_set(struct ui_table *tbl, int y, int x);
extern void ui_table_height_set(struct ui_table *tbl, int height);

extern void ui_table_col_add(struct ui_table *tbl, uint32_t id, const char *name,
			     uint32_t len);
extern void ui_table_col_color_set(struct ui_table *tbl, int col_id, int color);
extern void ui_table_col_align_set(struct ui_table *tbl, int col_id, enum ui_align align);
extern void ui_table_col_delim_set(struct ui_table *tbl, const char *delim);

extern void ui_table_row_add(struct ui_table *tbl);
extern void ui_table_row_show(struct ui_table *tbl);
extern void ui_table_row_col_set(struct ui_table *tbl, uint32_t col_id,
				 const char *str);

extern void ui_table_header_color_set(struct ui_table *tbl, int color);
extern void ui_table_header_print(struct ui_table *tbl);

extern void ui_table_event_send(struct ui_table *tbl, enum ui_event_id id);
extern void ui_table_data_iter_set(struct ui_table *tbl, void * (* iter)(void *data));
extern void ui_table_data_bind_set(struct ui_table *tbl,
				   void (* bind)(struct ui_table *tbl, const void *data));
extern void ui_table_data_bind(struct ui_table *tbl);
extern int ui_table_data_count(struct ui_table *tbl);
extern int ui_table_scroll_height(struct ui_table *tbl);

extern struct ui_tab *ui_tab_create(void);
extern void ui_tab_destroy(struct ui_tab *tab);
extern void ui_tab_pos_set(struct ui_tab *tab, int y, int x);
extern void ui_tab_event_cb_set(struct ui_tab *tab, ui_tab_event_cb cb);
extern void ui_tab_active_color_set(struct ui_tab *tab, int color);
extern void ui_tab_show(struct ui_tab *tab);
extern void ui_tab_entry_add(struct ui_tab *tab, uint32_t id, const char *name);
extern void ui_tab_event_send(struct ui_tab *tab, uint32_t id);

#endif /* UI_H */
