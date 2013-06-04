#ifndef SIG_H
#define SIG_H

extern void register_signal(int signal, void (*handler)(int));
extern void register_signal_f(int signal, void (*handler)(int), int flags);

#endif /* SIG_H */
