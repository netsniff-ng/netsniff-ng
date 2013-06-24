#include <curses.h>

#include "screen.h"

WINDOW *screen_init(bool israw)
{
	WINDOW *screen = initscr();

	if (israw)
		raw();
	noecho();
	cbreak();
	nodelay(screen, TRUE);
	keypad(stdscr, TRUE);
	refresh();
	wrefresh(screen);

	return screen;
}

void screen_end(void)
{
	endwin();
}
