#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fmtmsg.h>
#include <fnmatch.h>
#include <ftw.h>
#include <limits.h>
#include <math.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_memory/memory.h>
#include <pthread.h>
#include <search.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utmpx.h>

static int    failures;
static size_t fault_resource_events;
static FILE  *outcome_stream;

#define P101_TEST_ERRNO_SENTINEL 0x5A5A

#ifdef __linux__
    #define P101_TEST_PLATFORM "linux"
#elif defined(__APPLE__)
    #define P101_TEST_PLATFORM "macos"
#elif defined(__FreeBSD__)
    #define P101_TEST_PLATFORM "freebsd"
#else
    #define P101_TEST_PLATFORM "posix"
#endif

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);                                                                                                                                                                                   \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

struct fault_state
{
    int checks;
    int code;
};

static void write_outcome(const char *wrapper, const char *domain, const char *symbol, int code, int passed)
{
    int written;

    if(outcome_stream == NULL)
    {
        return;
    }
    written = fprintf(outcome_stream, "P101WRAPPER\t1\tFAULT\t%s\tlib_memory\t%s\t%s\t%s\t%d\t%s\n", P101_TEST_PLATFORM, wrapper, domain, symbol, code, passed ? "PASS" : "FAIL");
    if(written < 0 || fflush(outcome_stream) != 0)
    {
        fprintf(stderr, "FAIL: cannot write wrapper outcome receipt\n");
        failures++;
    }
}

static int fail_next_call(const struct p101_env *env, const char *call_name, void *user_data)
{
    struct fault_state *state;

    (void)env;
    (void)call_name;
    state = user_data;
    state->checks++;
    return state->code;
}

static void count_fd_event(const struct p101_env *env, p101_env_fd_event event, int fd, const char *file_name, const char *function_name, int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)fd;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

static void count_alloc_event(const struct p101_env *env, p101_env_alloc_event event, const void *ptr, const void *new_ptr, size_t size, const char *file_name, const char *function_name, int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)ptr;
    (void)new_ptr;
    (void)size;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

static void count_resource_event(const struct p101_env *env, p101_env_resource_kind event, const char *resource_class, const char *resource_id, const char *related_id, size_t size, const char *metadata, const char *file_name, const char *function_name,
                                 int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)resource_class;
    (void)resource_id;
    (void)related_id;
    (void)size;
    (void)metadata;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

/* P101_TEST_CASE(p101_mlock) */
static void test_p101_mlock(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "ENOMEM", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAGAIN, EINVAL, ENOMEM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "ENOMEM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM", "EPERM"};
#else
    static const int         errors[]      = {EAGAIN, EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "ENOMEM", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_mlock(env, err, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_mlock", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            int native_result = p101_mlock(native_env, native_err, NULL, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_mlockall) */
static void test_p101_mlockall(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAGAIN, EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "ENOMEM", "EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAGAIN, EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "ENOMEM", "EPERM"};
#else
    static const int         errors[]      = {EAGAIN, EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "ENOMEM", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_mlockall(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_mlockall", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            int native_result = p101_mlockall(native_env, native_err, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_mmap) */
static void test_p101_mmap(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_2[64];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAGAIN, EBADF, EINVAL, EMFILE, ENODEV, ENOMEM, ENOTSUP, ENXIO, EOVERFLOW};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EBADF", "EINVAL", "EMFILE", "ENODEV", "ENOMEM", "ENOTSUP", "ENXIO", "EOVERFLOW"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EBADF, EINVAL, ENODEV, ENOMEM, ENXIO, EOVERFLOW};
    static const char *const error_names[] = {"EACCES", "EBADF", "EINVAL", "ENODEV", "ENOMEM", "ENXIO", "EOVERFLOW"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EBADF, EINVAL, ENODEV, ENOMEM, ENOTSUP};
    static const char *const error_names[] = {"EACCES", "EBADF", "EINVAL", "ENODEV", "ENOMEM", "ENOTSUP"};
#else
    static const int         errors[]      = {EACCES, EAGAIN, EBADF, EINVAL, EMFILE, ENODEV, ENOMEM, ENOTSUP, ENXIO, EOVERFLOW};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EBADF", "EINVAL", "EMFILE", "ENODEV", "ENOMEM", "ENOTSUP", "ENXIO", "EOVERFLOW"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        void *result = p101_mmap(env, err, argument_2, 0, 0, 0, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (MAP_FAILED));
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_mmap", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            unsigned char native_argument_2[4096] = {0};
            void         *native_result           = p101_mmap(native_env, native_err, native_argument_2, 0, 0, 0, 0, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_mprotect) */
static void test_p101_mprotect(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_2[64];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EACCES, EINVAL, ENOMEM};
    static const char *const error_names[] = {"EACCES", "EINVAL", "ENOMEM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EINVAL, ENOMEM, ENOTSUP};
    static const char *const error_names[] = {"EACCES", "EINVAL", "ENOMEM", "ENOTSUP"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EINVAL, ENOTSUP};
    static const char *const error_names[] = {"EACCES", "EINVAL", "ENOTSUP"};
#else
    static const int         errors[]      = {EACCES, EAGAIN, EINVAL, ENOMEM, ENOTSUP};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EINVAL", "ENOMEM", "ENOTSUP"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_mprotect(env, err, argument_2, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_mprotect", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            unsigned char native_argument_2[4096] = {0};
            int           native_result           = p101_mprotect(native_env, native_err, native_argument_2, 0, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_msync) */
static void test_p101_msync(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_2[64];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EBUSY, EINVAL, ENOMEM};
    static const char *const error_names[] = {"EBUSY", "EINVAL", "ENOMEM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBUSY, EINVAL, EIO, ENOMEM};
    static const char *const error_names[] = {"EBUSY", "EINVAL", "EIO", "ENOMEM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBUSY, EINVAL, EIO, ENOMEM};
    static const char *const error_names[] = {"EBUSY", "EINVAL", "EIO", "ENOMEM"};
#else
    static const int         errors[]      = {EBUSY, EINVAL, ENOMEM};
    static const char *const error_names[] = {"EBUSY", "EINVAL", "ENOMEM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_msync(env, err, argument_2, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_msync", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            unsigned char native_argument_2[4096] = {0};
            int           native_result           = p101_msync(native_env, native_err, native_argument_2, 0, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_munlock) */
static void test_p101_munlock(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "ENOMEM", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM", "EPERM"};
#else
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_munlock(env, err, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_munlock", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            int native_result = p101_munlock(native_env, native_err, NULL, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_munlockall) */
static void test_p101_munlockall(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EINVAL, ENOMEM, EPERM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_munlockall(env, err);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_munlockall", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            int native_result = p101_munlockall(native_env, native_err);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_munmap) */
static void test_p101_munmap(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_2[64];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAGAIN, EBADF, EEXIST, EINVAL, ENFILE, ENODEV, ENOMEM, EOVERFLOW, EPERM, ETXTBSY};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EBADF", "EEXIST", "EINVAL", "ENFILE", "ENODEV", "ENOMEM", "EOVERFLOW", "EPERM", "ETXTBSY"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL};
    static const char *const error_names[] = {"EINVAL"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EINVAL};
    static const char *const error_names[] = {"EINVAL"};
#else
    static const int         errors[]      = {EINVAL};
    static const char *const error_names[] = {"EINVAL"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_munmap(env, err, argument_2, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_munmap", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            unsigned char native_argument_2[4096] = {0};
            int           native_result           = p101_munmap(native_env, native_err, native_argument_2, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_posix_madvise) */
static void test_p101_posix_madvise(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_2[64];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#else
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_posix_madvise(env, err, argument_2, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_posix_madvise", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            unsigned char native_argument_2[4096] = {0};
            int           native_result           = p101_posix_madvise(native_env, native_err, native_argument_2, 0, 0);
            (void)native_result;
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

/* P101_TEST_CASE(p101_posix_memalign) */
static void test_p101_posix_memalign(struct p101_env *env, struct p101_error *err)
{
    void         *argument_2[4];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#else
    static const int         errors[]      = {EINVAL, ENOMEM};
    static const char *const error_names[] = {"EINVAL", "ENOMEM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_posix_memalign(env, err, argument_2, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_posix_memalign", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
    {
        int   native_status = 0;
        pid_t native_pid    = fork();

        EXPECT(native_pid >= 0);
        if(native_pid == 0)
        {
            struct p101_error *native_err;
            struct p101_env   *native_env;

            (void)alarm(2U);
            (void)unsetenv("P101_CALL_LOG");
            (void)unsetenv("P101_RESOURCE_LOG");
            native_err = p101_error_create(false);
            if(native_err == NULL)
            {
                _Exit(77);
            }
            native_env = p101_env_create(native_err, NULL);
            if(native_env == NULL)
            {
                p101_error_destroy(native_err);
                _Exit(77);
            }
            void *native_argument_2 = NULL;
            int   native_result     = p101_posix_memalign(native_env, native_err, &native_argument_2, sizeof(void *), 16U);
            (void)native_result;
            free(native_argument_2);
            p101_env_destroy(native_env);
            p101_error_destroy(native_err);
            _Exit(EXIT_SUCCESS);
        }
        if(native_pid > 0)
        {
            EXPECT(waitpid(native_pid, &native_status, 0) == native_pid);
            EXPECT(WIFEXITED(native_status));
            if(WIFEXITED(native_status))
            {
                EXPECT(WEXITSTATUS(native_status) == EXIT_SUCCESS);
            }
        }
        p101_error_reset(err);
    }
}

int main(void)
{
    const char        *outcome_path;
    struct p101_error *err;
    struct p101_env   *env;

    outcome_path = getenv("P101_WRAPPER_OUTCOME_LOG");
    if(outcome_path != NULL && outcome_path[0] != '\0')
    {
        outcome_stream = fopen(outcome_path, "a");
        if(outcome_stream == NULL)
        {
            fprintf(stderr, "FAIL: cannot open wrapper outcome receipt\n");
            return EXIT_FAILURE;
        }
    }
    err = p101_error_create(false);
    if(err == NULL)
    {
        if(outcome_stream != NULL)
        {
            (void)fclose(outcome_stream);
        }
        return EXIT_FAILURE;
    }
    env = p101_env_create(err, NULL);
    if(env == NULL)
    {
        p101_error_destroy(err);
        if(outcome_stream != NULL)
        {
            (void)fclose(outcome_stream);
        }
        return EXIT_FAILURE;
    }
    p101_env_set_fd_observer(env, count_fd_event, NULL);
    p101_env_set_alloc_observer(env, count_alloc_event, NULL);
    p101_env_set_resource_observer(env, count_resource_event, NULL);
    test_p101_mlock(env, err);
    test_p101_mlockall(env, err);
    test_p101_mmap(env, err);
    test_p101_mprotect(env, err);
    test_p101_msync(env, err);
    test_p101_munlock(env, err);
    test_p101_munlockall(env, err);
    test_p101_munmap(env, err);
    test_p101_posix_madvise(env, err);
    test_p101_posix_memalign(env, err);
    p101_env_destroy(env);
    p101_error_destroy(err);
    if(outcome_stream != NULL && fclose(outcome_stream) != 0)
    {
        fprintf(stderr, "FAIL: cannot close wrapper outcome receipt\n");
        failures++;
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
