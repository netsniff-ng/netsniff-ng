#ifndef SCREEN_H
#define SCREEN_H

#include <curses.h>

enum colors {
	BLACK   = COLOR_BLACK,
	RED     = COLOR_RED,
	GREEN   = COLOR_GREEN,
	YELLOW  = COLOR_YELLOW,
	BLUE    = COLOR_BLUE,
	MAGENTA = COLOR_MAGENTA,
	CYAN    = COLOR_CYAN,
	WHITE   = COLOR_WHITE,
};

#define COLOR_MASK(fg, bg) ((fg) + (bg) * (COLOR_WHITE + 1))
#define COLOR(fg, bg) COLOR_PAIR(COLOR_MASK((fg), (bg)))
#define INIT_COLOR(fg, bg) init_pair(COLOR_MASK((fg), (bg)), (fg), (bg))
#define COLOR_ON(fg, bg) attron(COLOR(fg, bg))
#define COLOR_OFF(fg, bg) attroff(COLOR(fg, bg))

extern WINDOW *screen_init(bool israw);
extern void screen_end(void);

#endif /* SCREEN_H */
