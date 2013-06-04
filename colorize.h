#ifndef COLORIZE_H
#define COLORIZE_H

#define colorize_start(fore)		"\033[" __##fore "m"
#define colorize_start_full(fore, back)	"\033[" __##fore ";" __on_##back "m"
#define colorize_end()			"\033[" __reset "m"

#endif /* COLORIZE_H */
