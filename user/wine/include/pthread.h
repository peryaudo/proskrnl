/*
 * pthread.h - the four pthread primitives win32u leans on, over Rtl.
 *
 * win32u's unix half locks with pthreads because on Wine it IS unix code.
 * Compiled as PE (GUI-2) the same sources run above ntdll, so the primitives
 * are re-expressed over what ntdll already exports (user/wine/dlls/win32u/glue.c).
 * The set is closed and small: mutexes (103 unlocks, 78 locks), one-time
 * init, and one rwlock in vulkan.c. Nothing here is a general pthread
 * implementation and it must not grow into one - if a new Wine source needs
 * a primitive that is missing, add it here deliberately.
 *
 * Deliberately free of Windows headers: this lands early in sources that
 * include <string.h> later, and winbase.h poisons str* once __WINESRC__ is
 * set. The lock word is the pointer an RTL_SRWLOCK is; glue.c does the
 * casting.
 *
 * A mutex is an SRW lock plus an owner/depth pair rather than an
 * RTL_CRITICAL_SECTION, because RTL_SRWLOCK is the one lock ntdll exposes
 * that a `= PTHREAD_MUTEX_INITIALIZER` static can zero-initialise into a
 * usable state - which is how almost every win32u lock is declared.
 * Recursion is tracked so that re-entering a mutex Wine declared
 * non-recursive says so on serial instead of deadlocking silently (Art. 12:
 * a wrong state is loud, never plausible).
 */
#ifndef PRSK_PTHREAD_H
#define PRSK_PTHREAD_H

/* --- mutexes -------------------------------------------------------------- */

#define PTHREAD_MUTEX_NORMAL    0
#define PTHREAD_MUTEX_RECURSIVE 1

typedef struct
{
    int type;
} pthread_mutexattr_t;

typedef struct
{
    void         *lock;       /* RTL_SRWLOCK */
    unsigned long owner;      /* tid of the holder, 0 when free */
    int           depth;      /* recursion depth */
    int           recursive;  /* set by pthread_mutexattr_settype */
} pthread_mutex_t;

#define PTHREAD_MUTEX_INITIALIZER { 0, 0, 0, 0 }

extern int pthread_mutexattr_init( pthread_mutexattr_t *attr );
extern int pthread_mutexattr_settype( pthread_mutexattr_t *attr, int type );
extern int pthread_mutexattr_destroy( pthread_mutexattr_t *attr );
extern int pthread_mutex_init( pthread_mutex_t *mutex, const pthread_mutexattr_t *attr );
extern int pthread_mutex_destroy( pthread_mutex_t *mutex );
extern int pthread_mutex_lock( pthread_mutex_t *mutex );
extern int pthread_mutex_unlock( pthread_mutex_t *mutex );

/* --- one-time initialisation ---------------------------------------------- */

typedef int pthread_once_t;
#define PTHREAD_ONCE_INIT 0

extern int pthread_once( pthread_once_t *once, void (*init)(void) );

/* --- rwlocks (vulkan.c only) ----------------------------------------------
 *
 * Exclusive on both sides: a reader takes the write lock too. Over-
 * serialising is always correct, and it avoids having to remember per
 * acquisition which half of the SRW lock to release - which a single shared
 * flag cannot do once two readers overlap. The only caller is vulkan.c,
 * whose backend never loads here (dlopen has nothing to give it). */

typedef struct
{
    void *lock;               /* RTL_SRWLOCK */
} pthread_rwlock_t;

typedef struct
{
    int unused;
} pthread_rwlockattr_t;

#define PTHREAD_RWLOCK_INITIALIZER { 0 }

extern int pthread_rwlock_init( pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr );
extern int pthread_rwlock_destroy( pthread_rwlock_t *lock );
extern int pthread_rwlock_rdlock( pthread_rwlock_t *lock );
extern int pthread_rwlock_wrlock( pthread_rwlock_t *lock );
extern int pthread_rwlock_unlock( pthread_rwlock_t *lock );

#endif /* PRSK_PTHREAD_H */
