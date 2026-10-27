#include <dlfcn.h>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { std::fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    auto run = reinterpret_cast<int (*)()>(dlsym(library, "hellas_gpu_smoke"));
    if (!run) { std::fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    int result = run();
    if (result == 0) std::puts("gfx1151: HIP library loaded, 256 device sums matched");
    return result;
}
