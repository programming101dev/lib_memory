# Project metadata
set(PROJECT_NAME "p101_memory")
set(PROJECT_VERSION "0.0.1")
set(PROJECT_DESCRIPTION "Memory mapping, locking, advice, and aligned allocation")
set(PROJECT_LANGUAGE "C")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(STANDARD_FLAGS
        -D_POSIX_C_SOURCE=200809L
        -D_XOPEN_SOURCE=700
        -Werror
)
set(DARWIN_STANDARD_FLAGS -D_DARWIN_C_SOURCE)
set(LINUX_STANDARD_FLAGS -D_GNU_SOURCE)
set(BSD_STANDARD_FLAGS -D_BSD_SOURCE -D__BSD_VISIBLE)

set(LIBRARY_TARGETS p101_memory)
set(p101_memory_SOURCES
        src/posix/sys/mman.c
        src/posix_optional/stdlib.c
        src/posix_optional/sys/mman.c
        src/posix_xsi/sys/mman.c
)
set(p101_memory_HEADERS
        include/p101_memory/memory.h
)
set(p101_memory_LINK_LIBRARIES
        p101_error
        p101_env
        p101_c
)

