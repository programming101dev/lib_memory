#ifndef LIBP101_MEMORY_MEMORY_H
#define LIBP101_MEMORY_MEMORY_H

/*
 * Copyright 2026 D'Arcy Smith.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 */

#include <p101_env/env.h>
#include <p101_error/attributes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int   p101_mlock(const struct p101_env *env, struct p101_error *err, const void *addr, size_t len);
    int   p101_mlockall(const struct p101_env *env, struct p101_error *err, int flags);
    void *p101_mmap(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int prot, int flags, int fildes, off_t off) P101_ATTR_WARN_UNUSED_RESULT;
    int   p101_mprotect(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int prot);
    int   p101_msync(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int flags);
    int   p101_munlock(const struct p101_env *env, struct p101_error *err, const void *addr, size_t len);
    int   p101_munlockall(const struct p101_env *env, struct p101_error *err);
    int   p101_munmap(const struct p101_env *env, struct p101_error *err, void *addr, size_t len);
    int   p101_posix_madvise(const struct p101_env *env, struct p101_error *err, void *addr, size_t len, int advice);
    int   p101_posix_memalign(const struct p101_env *env, struct p101_error *err, void **memptr, size_t alignment, size_t size) P101_ATTR_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_MEMORY_MEMORY_H
