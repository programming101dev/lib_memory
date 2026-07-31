#include <errno.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_memory/memory.h>
#include <stdio.h>
#include <stdlib.h>

static int failures;

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
};

static int fail_next_call(const struct p101_env *env, const char *call_name, void *user_data)
{
    struct fault_state *state;

    (void)env;
    (void)call_name;
    state = user_data;
    state->checks++;
    return EIO;
}

/* P101_TEST_CASE(p101_mlock) */
static void test_p101_mlock(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_mlock(env, err, NULL, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_mlockall) */
static void test_p101_mlockall(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_mlockall(env, err, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_mmap) */
static void test_p101_mmap(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    void *result = p101_mmap(env, err, NULL, 0, 0, 0, 0, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_mprotect) */
static void test_p101_mprotect(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_mprotect(env, err, NULL, 0, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_msync) */
static void test_p101_msync(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_msync(env, err, NULL, 0, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_munlock) */
static void test_p101_munlock(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_munlock(env, err, NULL, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_munlockall) */
static void test_p101_munlockall(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_munlockall(env, err);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_munmap) */
static void test_p101_munmap(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_munmap(env, err, NULL, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_posix_madvise) */
static void test_p101_posix_madvise(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_posix_madvise(env, err, NULL, 0, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_posix_memalign) */
static void test_p101_posix_memalign(struct p101_env *env, struct p101_error *err)
{
    struct fault_state state = {0};

    p101_env_set_fault_injector(env, fail_next_call, &state);
    int result = p101_posix_memalign(env, err, NULL, 0, 0);
    (void)result;
    EXPECT(state.checks == 1);
    EXPECT(p101_error_has_error(err));
    p101_error_reset(err);
    p101_env_set_fault_injector(env, NULL, NULL);
}

int main(void)
{
    struct p101_error *err;
    struct p101_env   *env;

    err = p101_error_create(false);
    if(err == NULL)
    {
        return EXIT_FAILURE;
    }
    env = p101_env_create(err, NULL);
    if(env == NULL)
    {
        p101_error_destroy(err);
        return EXIT_FAILURE;
    }
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
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
