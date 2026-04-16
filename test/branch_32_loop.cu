#include <stdint.h>

extern "C" __global__ void branch_32_loop(uint32_t *output, int n) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid >= n)
    return;

  uint32_t lane = threadIdx.x & 31;
  uint32_t val = 0;

  volatile uint32_t bits = lane ^ (uint32_t)tid;

#pragma unroll
  for (int i = 0; i < 32; i++) {
    if (bits & (1u << i)) {
      val += (1u << i);
      val ^= ((uint32_t)i * 7u);
    } else {
      val -= (1u << i);
      val ^= ((uint32_t)i * 13u);
    }
  }

  output[tid] = val;
}
