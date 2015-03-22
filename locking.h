#ifndef LOCKING_H
#define LOCKING_H

#include <pthread.h>

struct spinlock {
	pthread_spinlock_t lock;
};

struct mutexlock {
	pthread_mutex_t lock;
};

#define MUTEXLOCK_INITIALIZER { .lock = PTHREAD_MUTEX_INITIALIZER }

struct rwlock {
	pthread_rwlock_t lock;
};

struct condlock {
	pthread_mutex_t lock;
	pthread_cond_t cond;
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

static inline int rwlock_init(struct rwlock *l)
{
	return -pthread_rwlock_init(&l->lock, 0);
}

static inline int rwlock_init2(struct rwlock *l,
			       pthread_rwlockattr_t *attr)
{
	return -pthread_rwlock_init(&l->lock, attr);
}

static inline void rwlock_destroy(struct rwlock *l)
{
	pthread_rwlock_destroy(&l->lock);
}

static inline void rwlock_rd_lock(struct rwlock *l)
{
	pthread_rwlock_rdlock(&l->lock);
}

static inline void rwlock_wr_lock(struct rwlock *l)
{
	pthread_rwlock_wrlock(&l->lock);
}

static inline void rwlock_unlock(struct rwlock *l)
{
	pthread_rwlock_unlock(&l->lock);
}

static inline void condlock_init(struct condlock *c)
{
	pthread_mutex_init(&c->lock, NULL);
	pthread_cond_init(&c->cond, NULL);
}

static inline void condlock_signal(struct condlock *c)
{
	pthread_mutex_lock(&c->lock);
	pthread_cond_signal(&c->cond);
	pthread_mutex_unlock(&c->lock);
}

static inline void condlock_wait(struct condlock *c)
{
	pthread_mutex_lock(&c->lock);
	pthread_cond_wait(&c->cond, &c->lock);
	pthread_mutex_unlock(&c->lock);
}

static inline void condlock_destroy(struct condlock *c)
{
	pthread_mutex_destroy(&c->lock);
	pthread_cond_destroy(&c->cond);
}

#endif /* LOCKING_H */
