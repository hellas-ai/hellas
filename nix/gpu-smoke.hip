#include <hip/hip_runtime.h>
#include <cstdio>

__global__ void add(const int* a, const int* b, int* out) {
    unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < 256) out[i] = a[i] + b[i];
}

extern "C" int hellas_gpu_smoke() {
    int a[256], b[256], out[256];
    for (int i = 0; i < 256; ++i) { a[i] = i; b[i] = 2 * i; }
    int *da = nullptr, *db = nullptr, *dc = nullptr;
    auto check = [](hipError_t error) {
        if (error != hipSuccess) std::fprintf(stderr, "HIP: %s\n", hipGetErrorString(error));
        return error == hipSuccess;
    };
    int result = 1;
    if (check(hipMalloc(&da, sizeof(a))) && check(hipMalloc(&db, sizeof(b))) &&
        check(hipMalloc(&dc, sizeof(out))) &&
        check(hipMemcpy(da, a, sizeof(a), hipMemcpyHostToDevice)) &&
        check(hipMemcpy(db, b, sizeof(b), hipMemcpyHostToDevice))) {
        hipLaunchKernelGGL(add, dim3(1), dim3(256), 0, 0, da, db, dc);
        if (check(hipGetLastError()) && check(hipDeviceSynchronize()) &&
            check(hipMemcpy(out, dc, sizeof(out), hipMemcpyDeviceToHost))) {
            result = 0;
            for (int i = 0; i < 256; ++i) {
                if (out[i] != 3 * i) {
                    std::fprintf(stderr, "sum[%d] = %d, expected %d\n", i, out[i], 3 * i);
                    result = 1;
                    break;
                }
            }
        }
    }
    if (dc && !check(hipFree(dc))) result = 1;
    if (db && !check(hipFree(db))) result = 1;
    if (da && !check(hipFree(da))) result = 1;
    return result;
}
