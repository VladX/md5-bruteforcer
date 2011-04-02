#ifdef USEGPU
 #define GPU_THREADS 1
#endif

#ifndef GPU_THREADS
 #define GPU_THREADS 0 // Использовать GPU?
#endif

#ifndef THREADS
 #define THREADS 1 // Общее количество потоков (CPU + GPU)
#endif

#undef I_SIZE
#define I_SIZE 15
