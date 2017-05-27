/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <curses.h>

#include "ui.h"
#include "str.h"
#include "screen.h"
#include "xmalloc.h"
#include "urcu-list-compat.h"

static struct ui_text *ui_text_alloc(size_t len)
{
	struct ui_text *text = xzmalloc(sizeof(*text));

	text->str = xzmalloc(sizeof(chtype) * len + 1);
	text->len = len;

	return text;
}

static void ui_text_len_set(struct ui_text *text, size_t len)
{
	if (text->len == len)
		return;

	if (text->slen + len > text->len) {
		text->str = xrealloc(text->str, sizeof(chtype) * len + 1);
		text->len = len;
	}

	text->slen = min(len, text->slen);
	text->str[text->slen] = 0;
}

static void ui_text_attr_insert(struct ui_text *text, int idx, int attr, const char *str)
{
	size_t slen = strlen(str);
	uint32_t i, j;

	if (idx + slen > text->len)
		ui_text_len_set(text, idx + slen);

	for (j = 0, i = idx; i < idx + slen; i++, j++)
		text->str[i] = str[j] | attr;
}

static void ui_text_free(struct ui_text *text)
{
	xfree(text->str);
	xfree(text);
}

void ui_table_init(struct ui_table *tbl)
{
	memset(tbl, 0, sizeof(*tbl));

	getsyx(tbl->y, tbl->x);

	tbl->rows_y  = tbl->y;
	tbl->width   = COLS;
	tbl->height  = LINES - 2;
	tbl->col_pad = 1;
	tbl->row     = ui_text_alloc(tbl->width);
	tbl->delim   = " ";

	CDS_INIT_LIST_HEAD(&tbl->cols);
}

void ui_table_uninit(struct ui_table *tbl)
{
	struct ui_col *col, *tmp;

	cds_list_for_each_entry_safe(col, tmp, &tbl->cols, entry)
		xfree(col);

	ui_text_free(tbl->row);
}

void ui_table_pos_set(struct ui_table *tbl, int y, int x)
{
	tbl->y      = y;
	tbl->x      = x;
	tbl->rows_y = y;
}

static struct ui_col *ui_table_col_get(struct ui_table *tbl, uint32_t id)
{
	struct ui_col *col;

	cds_list_for_each_entry(col, &tbl->cols, entry) {
		if (col->id == id)
			return col;
	}

	bug();
}

static void __ui_table_pos_update(struct ui_table *tbl)
{
	struct ui_col *col;
	uint32_t pos = 0;

	cds_list_for_each_entry(col, &tbl->cols, entry) {
		col->pos  = pos;
		pos      += col->len + tbl->col_pad;
	}
}

void ui_table_col_add(struct ui_table *tbl, uint32_t id, const char *name, uint32_t len)
{
	struct ui_col *col = xzmalloc(sizeof(*col));

	col->id    = id;
	col->name  = name;
	col->len   = len;
	col->align = UI_ALIGN_LEFT;

	cds_list_add_tail(&col->entry, &tbl->cols);

	__ui_table_pos_update(tbl);
}

void ui_table_col_color_set(struct ui_table *tbl, int col_id, int color)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	col->color = color;
}

void ui_table_col_align_set(struct ui_table *tbl, int col_id, enum ui_align align)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	col->align = align;
}

void ui_table_col_delim_set(struct ui_table *tbl, const char *delim)
{
	tbl->delim = delim;
}

void ui_table_row_add(struct ui_table *tbl)
{
	tbl->rows_y++;
}

void ui_table_clear(struct ui_table *tbl)
{
	int y;

	tbl->rows_y = tbl->y;

	for (y = tbl->y + 1; y < tbl->y + tbl->height; y++) {
		mvprintw(y, tbl->x, "%*s", tbl->width, " ");
	}
}

#define UI_ALIGN_COL(col) (((col)->align == UI_ALIGN_LEFT) ? "%-*.*s" : "%*.*s")

void ui_table_row_show(struct ui_table *tbl)
{
	mvaddchstr(tbl->rows_y, tbl->x, tbl->row->str + tbl->scroll_x);
	ui_text_len_set(tbl->row, 0);
}

static void __ui_table_row_print(struct ui_table *tbl, struct ui_col *col,
				 int color, const char *str)
{
	char tmp[128];

	slprintf(tmp, sizeof(tmp), UI_ALIGN_COL(col), col->len, col->len, str);
	ui_text_attr_insert(tbl->row, col->pos, color, tmp);

	slprintf(tmp, sizeof(tmp), "%*s", tbl->col_pad, tbl->delim);
	ui_text_attr_insert(tbl->row, col->pos + col->len, color, tmp);
}

void ui_table_row_col_set(struct ui_table *tbl, uint32_t col_id, const char *str)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	__ui_table_row_print(tbl, col, col->color, str);
}

void ui_table_header_color_set(struct ui_table *tbl, int color)
{
	tbl->hdr_color = color;
}

void ui_table_height_set(struct ui_table *tbl, int height)
{
	tbl->height = height;
}

void ui_table_header_print(struct ui_table *tbl)
{
	struct ui_col *col;

	attron(tbl->hdr_color);
	mvprintw(tbl->y, tbl->x, "%*s", tbl->width, " ");
	attroff(tbl->hdr_color);

	cds_list_for_each_entry(col, &tbl->cols, entry) {
		__ui_table_row_print(tbl, col, tbl->hdr_color, col->name);
	}

	ui_table_row_show(tbl);
}

#define SCROLL_X_STEP 10

void ui_table_event_send(struct ui_table *tbl, enum ui_event_id evt_id)
{
	switch (evt_id) {
	case UI_EVT_SCROLL_RIGHT:
		tbl->scroll_x += SCROLL_X_STEP;
		break;

	case UI_EVT_SCROLL_LEFT:
		tbl->scroll_x -= SCROLL_X_STEP;
		if (tbl->scroll_x < 0)
			tbl->scroll_x = 0;
		break;

	case UI_EVT_SCROLL_UP:
		tbl->scroll_y--;
		if (tbl->scroll_y < 0)
			tbl->scroll_y = 0;
		break;

	case UI_EVT_SCROLL_DOWN:
		tbl->scroll_y++;
		break;

	default: /* pass the rest events */
		return;
	}
}

void ui_table_data_iter_set(struct ui_table *tbl, void * (* iter)(void *data))
{
	tbl->data_iter = iter;
}

void ui_table_data_bind_set(struct ui_table *tbl,
			    void (* bind)(struct ui_table *tbl, const void *data))
{
	tbl->data_bind = bind;
}

void ui_table_data_bind(struct ui_table *tbl)
{
	void *data;
	int i = 0;

	bug_on(!tbl);
	bug_on(!tbl->data_iter);
	bug_on(!tbl->data_bind);

	ui_table_clear(tbl);
	ui_table_header_print(tbl);

	tbl->data_count = 0;

	data = tbl->data_iter(NULL);
	for (; data; data = tbl->data_iter(data)) {
		tbl->data_count++;

		if (i++ < tbl->scroll_y)
			continue;

		tbl->data_bind(tbl, data);
	}

	if (tbl->scroll_y > i)
		tbl->scroll_y = i;
}

int ui_table_data_count(struct ui_table *tbl)
{
	return tbl->data_count;
}

int ui_table_scroll_height(struct ui_table *tbl)
{
	return tbl->scroll_y;
}

struct ui_tab *ui_tab_create(void)
{
	struct ui_tab *tab;

	tab = xzmalloc(sizeof(*tab));

	ui_table_init(&tab->tbl);
	ui_table_col_delim_set(&tab->tbl, "|");
	tab->tbl.width = 0;

	return tab;
}

void ui_tab_destroy(struct ui_tab *tab)
{
	ui_table_uninit(&tab->tbl);
	xfree(tab);
}

void ui_tab_pos_set(struct ui_tab *tab, int y, int x)
{
	ui_table_pos_set(&tab->tbl, y, x);
}

void ui_tab_event_cb_set(struct ui_tab *tab, ui_tab_event_cb cb)
{
	tab->on_tab_event = cb;
}

void ui_tab_active_color_set(struct ui_tab *tab, int color)
{
	ui_table_header_color_set(&tab->tbl, color);
	tab->color = color;
}

void ui_tab_show(struct ui_tab *tab)
{
	struct ui_col *col;

	if (tab->on_tab_event)
		tab->on_tab_event(tab, UI_TAB_EVT_OPEN, tab->active->id);

	cds_list_for_each_entry(col, &tab->tbl.cols, entry)
		__ui_table_row_print(&tab->tbl, col, col->color, col->name);

	ui_table_row_show(&tab->tbl);
}

void ui_tab_entry_add(struct ui_tab *tab, uint32_t id, const char *name)
{
	struct ui_col *col;

	ui_table_col_add(&tab->tbl, id, name, strlen(name) + 1);

	col = ui_table_col_get(&tab->tbl, id);

	if (!tab->active)
		tab->active = col;

	if (tab->active == col)
		ui_table_col_color_set(&tab->tbl, id, tab->color);
	else
		ui_table_col_color_set(&tab->tbl, id, tab->color | A_REVERSE);
}

void ui_tab_event_send(struct ui_tab *tab, uint32_t id)
{
	struct ui_col *curr, *next;

	if (id != UI_EVT_SELECT_NEXT)
		return;

	curr = tab->active;

	if (curr == cds_list_last_entry(&tab->tbl.cols, struct ui_col, entry))
		next = cds_list_first_entry(&tab->tbl.cols, struct ui_col, entry);
	else
		next = cds_list_next_entry(curr, entry);

	curr->color = tab->color | A_REVERSE;
	next->color = tab->color;

	tab->active = next;
}
