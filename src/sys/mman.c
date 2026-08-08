/*
 * Copyright 2026 D'Arcy Smith.
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

#include "p101_memory/sys/p101_mman.h"
#include <p101_env/resource_classes.h>
#include <p101_env/wrapper.h>

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

#include <sys/mman.h>

void *p101_mmap(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    void *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, MAP_FAILED);
    errno   = 0;
    ret_val = mmap(addr, len, prot, flags, fildes, off);

    if(ret_val == MAP_FAILED)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        P101_TRACK_POINTER_RESOURCE_ACQUIRE(env, P101_RESOURCE_CLASS_MAPPING, ret_val, len, NULL);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_mprotect(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int prot)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = mprotect(addr, len, prot);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_munmap(const struct p101_env *env, struct p101_error *err, void *addr, size_t len)
{
    char resource_id[P101_ENV_POINTER_RESOURCE_ID_SIZE];
    int  ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);

    /*
     * munmap unmaps the pages addr names, so spell the id while the mapping
     * is still there rather than reading a pointer into unmapped storage.
     */
    p101_env_pointer_resource_id(resource_id, sizeof(resource_id), addr);
    errno   = 0;
    ret_val = munmap(addr, len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        /*
         * P101_TRACK_RESOURCE_RELEASE pins size to 0U, so call the tracking
         * function directly to keep the mapping length in the release
         * record; p101_mmap() records the same value on acquire.
         */
        p101_env_track_resource(env, P101_ENV_RESOURCE_RELEASE, P101_RESOURCE_CLASS_MAPPING, resource_id, NULL, len, NULL, __FILE__, __func__, __LINE__);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

/*
 * Copyright 2021-2024 D'Arcy Smith.
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

int p101_mlock(const struct p101_env *env, struct p101_error *err, const void *addr, size_t len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = mlock(addr, len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_mlockall(const struct p101_env *env, struct p101_error *err, int flags)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = mlockall(flags);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_munlock(const struct p101_env *env, struct p101_error *err, const void *addr, size_t len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = munlock(addr, len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_munlockall(const struct p101_env *env, struct p101_error *err)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = munlockall();

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_posix_madvise(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int advice)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_CODE(env, err, ret_val);
    ret_val = posix_madvise(addr, len, advice);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, ret_val);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

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
