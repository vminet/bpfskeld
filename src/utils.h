#pragma once

/* variables/functions attributes */
#define __cleanup(x) __attribute__ ((__cleanup__(x)))

/* stringify - turn an expression into a string literal */
#define __stringify(x) #x
#define stringify(x)   __stringify(x)

/* paste - concatenate macro arguments after expansion */
#define __paste(a, b) a ## b
#define paste(a, b) __paste(a, b)

/* gensym - generate a unique identifier */
#define gensym() paste(__gensym_, __COUNTER__)

/* take_ptr - reads and returns a pointer, resetting it to 0 */
#define take_ptr(ptr) __take_ptr(ptr, gensym(), gensym())
#define __take_ptr(ptr, a, b) \
({ \
	typeof (ptr) *a = &(ptr); \
	typeof (ptr) b = *a; \
	*a = 0; \
	b; \
})

/* log_error_errno - log an error, set errno and return the error */
extern int log_error_errno (int err, const char *fmt, ...);

/* sigprocmask_many - change signal mask with varargs */
extern int sigprocmask_many (int how, sigset_t *old, ...);

/* privdrop - drop privileges and run as regular user */
extern int privdrop (const char *user);

/* sd_notify helpers */
#define NOTIFY_READY "READY=1\n" "STATUS=Processing requests..."
#define NOTIFY_STOPPING "STOPPING=1\n" "STATUS=Shutting down..."

extern const char *notify_start (const char *start, const char *stop);
extern void notify_on_cleanup (const char **p);
