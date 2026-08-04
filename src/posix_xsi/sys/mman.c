#include "p101_memory/memory.h"
#include <p101_env/wrapper.h>
#include <sys/mman.h>

int p101_msync(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int flags)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = msync(addr, len, flags);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}
