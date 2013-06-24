#ifndef SCREEN_H
#define SCREEN_H

#include <curses.h>

extern WINDOW *screen_init(bool israw);
extern void screen_end(void);

#endif /* SCREEN_H */
