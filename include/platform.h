#ifndef PLATFORM_H
#define PLATFORM_H

/*
 * Platform Detection and Configuration
 */

/* Platform detection */
#if defined(__linux__)
#define PLATFORM_LINUX 1
#define PLATFORM_NAME "Linux"
#define HAS_EBPF 1
#elif defined(__APPLE__) && defined(__MACH__)
#define PLATFORM_MACOS 1
#define PLATFORM_NAME "macOS"
#define HAS_EBPF 0
#define HAS_BPF 1
#elif defined(__FreeBSD__)
#define PLATFORM_FREEBSD 1
#define PLATFORM_NAME "FreeBSD"
#define HAS_BPF 1
#else
#error "Unsupported platform"
#endif

/* Compiler attributes */
#ifdef __GNUC__
#define PACKED __attribute__((packed))
#define ALIGNED(x) __attribute__((aligned(x)))
#define UNUSED __attribute__((unused))
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define PACKED
#define ALIGNED(x)
#define UNUSED
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

/* Memory barriers */
#ifdef PLATFORM_LINUX
#define MEMORY_BARRIER() __sync_synchronize()
#else
#define MEMORY_BARRIER() __asm__ __volatile__("" ::: "memory")
#endif

/* Cache line size for alignment */
#define CACHE_LINE_SIZE 64

/* Maximum interface name length */
#define IFNAMSIZ_MAX 16

/* Version info */
#define OBSERVER_VERSION_MAJOR 1
#define OBSERVER_VERSION_MINOR 0
#define OBSERVER_VERSION_PATCH 0

#define OBSERVER_VERSION_STRING "1.0.0"

#endif /* PLATFORM_H */