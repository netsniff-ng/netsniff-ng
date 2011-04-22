/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef LOCKING_H
#define LOCKING_H

#include <pthread.h>

struct spinlock {
	pthread_spinlock_t lock;
};

struct mutexlock {
	pthread_mutex_t lock;
};

static inline int spinlock_init(struct spinlock *l)
{
	return -pthread_spin_init(&l->lock, 0);
}

static inline void spinlock_destroy(struct spinlock *l)
{
	pthread_spin_destroy(&l->lock);
}

static inline void spinlock_lock(struct spinlock *l)
{
	pthread_spin_lock(&l->lock);
}

static inline void spinlock_unlock(struct spinlock *l)
{
	pthread_spin_unlock(&l->lock);
}

static inline int mutexlock_init(struct mutexlock *l)
{
	return -pthread_mutex_init(&l->lock, 0);
}

static inline void mutexlock_destroy(struct mutexlock *l)
{
	pthread_mutex_destroy(&l->lock);
}

static inline void mutexlock_lock(struct mutexlock *l)
{
	pthread_mutex_lock(&l->lock);
}

static inline void mutexlock_unlock(struct mutexlock *l)
{
	pthread_mutex_unlock(&l->lock);
}

#endif /* LOCKING_H */

