/*
 * Copyright 2022-2024 D'Arcy Smith.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "p101_memory/memory.h"
#include <p101_env/wrapper.h>
#include <sys/mman.h>

void *p101_mmap(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    void *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, MAP_FAILED);
    errno   = 0;
    ret_val = mmap(addr, len, prot, flags, fildes, off);

    if(ret_val == MAP_FAILED)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        P101_TRACK_POINTER_RESOURCE_ACQUIRE(env, "mapping", ret_val, len, NULL);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_mprotect(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int prot)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    errno   = 0;
    ret_val = mprotect(addr, len, prot);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_munmap(const struct p101_env *env, struct p101_error *err, void *addr, size_t len)
{
    char resource_id[P101_ENV_POINTER_RESOURCE_ID_SIZE];
    int  ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    p101_env_pointer_resource_id(resource_id, sizeof(resource_id), addr);
    errno   = 0;
    ret_val = munmap(addr, len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        P101_TRACK_RESOURCE_RELEASE(env, "mapping", resource_id, NULL);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}
