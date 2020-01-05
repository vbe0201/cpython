#include <sys/reent.h>

#include "3ds/result.h"
#include "3ds/svc.h"
#include "3ds/synchronization.h"
#include "3ds/thread.h"
#include "3ds/types.h"

#include "condvar.h"

#define THREAD_STACK_SIZE 0x1000
#define THREAD_PRIORITY 0x20
#define THREAD_CPU_ID -2

#define THREADVARS_MAGIC 0x21545624 // !TV$

// Keep this structure under 0x80 bytes
typedef struct
{
    // Magic value used to check if the struct is initialized
    u32 magic;

    // Pointer to the current thread (if exists)
    Thread thread_ptr;

    // Pointer to this thread's newlib state
    struct _reent* reent;

    // Pointer to this thread's thread-local segment
    void* tls_tp; // !! Keep offset in sync inside __aebi_read_tp !!
} ThreadVars;

static inline ThreadVars* getThreadVars(void)
{
    return (ThreadVars *)getThreadLocalStorage();
}

/*
 * Initialization.
 */
static void
_noop(void)
{
}

static void
PyThread__init_thread(void)
{
    Thread t = threadCreate((void *)_noop, NULL, THREAD_STACK_SIZE, THREAD_PRIORITY, THREAD_CPU_ID, false);
    threadJoin(t, U64_MAX);
    threadFree(t);
}

/*
 * Thread support.
 */
typedef struct {
    ThreadFunc func;
    void *arg;
} _wrapper_args;

static void
_wrapper_func(_wrapper_args *args)
{
    args->func(args->arg);
}

long
PyThread_start_new_thread(void (*func)(void *), void *arg)
{
    dprintf(("PyThread_start_new_thread called\n"));
    if (!initialized)
        PyThread_init_thread();
    
    _wrapper_args wargs;
    wargs.func = func;
    wargs.arg = arg;

    PyMem_RawMalloc(sizeof(Thread));
    Thread t = threadCreate((ThreadFunc)_wrapper_func, &wargs, THREAD_STACK_SIZE, THREAD_PRIORITY, THREAD_CPU_ID, true);

    return !t ? -1 : 0;
}

long
PyThread_get_thread_ident(void)
{
    if (!initialized)
        PyThread_init_thread();
    
    Thread t = getThreadVars()->thread_ptr;
    return (long)t + 1;
}

void
PyThread_exit_thread(void)
{
    dprintf(("PyThread_exit_thread called\n"));
    if (!initialized)
        exit(0);
    
    Thread t = getThreadVars()->thread_ptr;
    threadExit(!t ? -1 : 0);
    PyMem_RawFree((void *)t);
}

/*
 * Lock support.
 */
typedef struct {
    char locked;
    PyCOND_T cond;
    PyMUTEX_T mut;
} _thread_lock;

PyThread_type_lock
PyThread_allocate_lock(void)
{

    dprintf(("PyThread_allocate_lock called\n"));
    if (!initialized)
        PyThread_init_thread();
    
    _thread_lock *lock = (_thread_lock *) PyMem_RawMalloc(sizeof(_thread_lock));
    lock->locked = 0;

    PyMUTEX_INIT(&lock->mut);

    PyCOND_INIT(&lock->cond, &lock->mut);

    //dprintf(("PyThread_allocate_lock() -> %p\n", lock));
    return (PyThread_type_lock) lock;
}

void
PyThread_free_lock(PyThread_type_lock lock)
{
    dprintf(("PyThread_free_lock(%p) called\n", lock));

    _thread_lock *thread_lock = (_thread_lock *) lock;
    if (!thread_lock)
        return;
    
    PyMem_RawFree((void *) thread_lock);
}

int
PyThread_acquire_lock(PyThread_type_lock lock, int waitflag)
{
    return PyThread_acquire_lock_timed(lock, waitflag ? -1 : 0, 0);
}

PyLockStatus
PyThread_acquire_lock_timed(PyThread_type_lock lock, PY_TIMEOUT_T microseconds,
                            int intr_flag)
{
    PyLockStatus success;
    int result;

    dprintf(("PyThread_acquire_lock_timed(%p, %lld, %d) called\n", lock, microseconds, intr_flag));

    _thread_lock *thread_lock = (_thread_lock *) lock;
    if (thread_lock->locked == 1 && microseconds == 0) {
        success = PY_LOCK_FAILURE;
        goto end;
    }

    PyMUTEX_LOCK(&thread_lock->mut);
    if (thread_lock->locked == 0)
        success = PY_LOCK_ACQUIRED;
    else if (microseconds == 0)
        success = PY_LOCK_FAILURE;
    else {
        success = PY_LOCK_FAILURE;
        while (success == PY_LOCK_FAILURE) {
            if (microseconds > 0) {
                result = PyCOND_TIMEDWAIT(&thread_lock->cond, &thread_lock->mut, microseconds);
                if (result == 1) /* timeout */
                    break;
            } else
                result = PyCOND_WAIT(&thread_lock->cond, &thread_lock->mut);
            
            if (intr_flag && result == 1 && thread_lock->locked) {
                /*
                 * Somehow we've been signaled but didn't get the lock.
                 * Return PY_LOCK_INTR to allow the caller to handle it
                 * and retry.
                 */
                success = PY_LOCK_INTR;
                break;
            } else if (!thread_lock->locked)
                success = PY_LOCK_ACQUIRED;
            else
                success = PY_LOCK_FAILURE;
        }
    }

    if (success == PY_LOCK_ACQUIRED)
        thread_lock->locked = 1;
    
    PyMUTEX_UNLOCK(&thread_lock->mut);

end:
    dprintf(("PyThread_acquire_lock_timed(%p, %lld, %d) -> %d\n",
	     lock, microseconds, intr_flag, success));
    return success;
}

void
PyThread_release_lock(PyThread_type_lock lock)
{
    dprintf(("PyThread_release_lock(%p) called\n", lock));

    _thread_lock *thread_lock = (_thread_lock *) lock;
    PyMUTEX_LOCK(&thread_lock->mut);
    thread_lock->locked = 0;
    PyCOND_SIGNAL(&thread_lock->cond);
    PyMUTEX_UNLOCK(&thread_lock->mut);
}

/* The following are only needed if native TLS support exists */
/* #define Py_HAVE_NATIVE_TLS */

#ifdef Py_HAVE_NATIVE_TLS
int
PyThread_create_key(void)
{
    int result;
    return result;
}

void
PyThread_delete_key(int key)
{

}

int
PyThread_set_key_value(int key, void *value)
{
    int ok;

    /* A failure in this case returns -1 */
    if (!ok)
        return -1;
    return 0;
}

void *
PyThread_get_key_value(int key)
{
    void *result;

    return result;
}

void
PyThread_delete_key_value(int key)
{

}

void
PyThread_ReInitTLS(void)
{

}

#endif
