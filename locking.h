/*
 * locking.h - macOS pthread_mutex replacement for pthread_spinlock
 */
#ifndef LOCKING_H
#define LOCKING_H

#include <pthread.h>

struct spinlock {
        pthread_mutex_t lock;
};

static inline int spinlock_init(struct spinlock *l)
{
        return -pthread_mutex_init(&l->lock, NULL);
}

static inline void spinlock_destroy(struct spinlock *l)
{
        pthread_mutex_destroy(&l->lock);
}

static inline void spinlock_lock(struct spinlock *l)
{
        pthread_mutex_lock(&l->lock);
}

static inline void spinlock_unlock(struct spinlock *l)
{
        pthread_mutex_unlock(&l->lock);
}

#endif /* LOCKING_H */
