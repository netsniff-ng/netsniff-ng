/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <curses.h>

#include "ui.h"
#include "xmalloc.h"

void ui_table_init(struct ui_table *tbl)
{
	memset(tbl, 0, sizeof(*tbl));

	getsyx(tbl->y, tbl->x);

	tbl->rows_y  = tbl->y;
	tbl->width   = COLS;
	tbl->height  = LINES - 2;
	tbl->col_pad = 1;

	INIT_LIST_HEAD(&tbl->cols);
}

void ui_table_uninit(struct ui_table *tbl)
{
	struct ui_col *col, *tmp;

	list_for_each_entry_safe(col, tmp, &tbl->cols, entry)
		xfree(col);
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

	list_for_each_entry(col, &tbl->cols, entry) {
		if (col->id == id)
			return col;
	}

	bug();
}

static void __ui_table_pos_update(struct ui_table *tbl)
{
	struct ui_col *col;
	uint32_t pos = tbl->x;

	list_for_each_entry(col, &tbl->cols, entry) {
		col->pos  = pos;
		pos      += col->len + tbl->col_pad;
	}
}

void ui_table_col_add(struct ui_table *tbl, uint32_t id, char *name, uint32_t len)
{
	struct ui_col *col = xzmalloc(sizeof(*col));

	col->id    = id;
	col->name  = name;
	col->len   = len;
	col->align = UI_ALIGN_LEFT;

	list_add_tail(&col->entry, &tbl->cols);

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

static void __ui_table_row_print(struct ui_table *tbl, struct ui_col *col,
				 const char *str)
{
	mvprintw(tbl->rows_y, col->pos, UI_ALIGN_COL(col), col->len, col->len, str);
	mvprintw(tbl->rows_y, col->pos + col->len, "%*s", tbl->col_pad, " ");
}

void ui_table_row_print(struct ui_table *tbl, uint32_t col_id, const char *str)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	attron(col->color);
	__ui_table_row_print(tbl, col, str);
	attroff(col->color);
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
	int max_width = tbl->width;
	int width = 0;

	attron(tbl->hdr_color);

	mvprintw(tbl->y, tbl->x, "%-*.*s", max_width - tbl->x, max_width - tbl->x, "");
	mvprintw(tbl->y, tbl->x, "");

	list_for_each_entry(col, &tbl->cols, entry) {
		__ui_table_row_print(tbl, col, col->name);
		width += col->len + tbl->col_pad;
	}

	mvprintw(tbl->y, width, "%*s", max_width - width, " ");
	attroff(tbl->hdr_color);
}
