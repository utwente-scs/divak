#include "rope.h"
#include "dummy.h"


#include <stdarg.h>
#include <string.h>
#include <unistd.h>

// reliable ways to get the adresses of the return address and old base pointer
#define OLD_BP_PTR __builtin_frame_address(0)
#define RET_ADDR_PTR (void *)((void **)OLD_BP_PTR + 1)

int dummy_glob_int;

enum overwrite_types { continuous, jumping };
static enum overwrite_types overwrite_type;

enum contexts { iso, svd };
static enum contexts context;

enum pointer_types { ret, baseptr, funcptr, structfuncptr, longjmpptr };
static enum pointer_types pointer_type;

enum locations { stack, data, bss };
static enum locations location;

char bss_buffer[512];
struct attackme bss_struct;
jmp_buf bss_jmp_buffer;
void *bss_func_ptr;

char data_buffer[512] = {'X'};
struct attackme data_struct = {'X'};
jmp_buf data_jmp_buffer = {'X'};
void *data_func_ptr = &dummy_function;

void assert(int b) {
    if (!b) {
        puts("Attack impossible\n");
        exit(1);
    }
}

void iso_tst() {
#ifdef ASAN
    char stack_buffer2[1024];
    struct attackme stack_struct;
    char stack_buffer[512];
    jmp_buf stack_jmp_buffer;
    void *stack_func_ptr = &dummy_function;
#else
    void *stack_func_ptr = &dummy_function;
    jmp_buf stack_jmp_buffer;
    char stack_buffer[512];
    struct attackme stack_struct;
    char stack_buffer2[1024];
#endif

    for (int i=0; i<511; i++)
        stack_buffer[i] = 'A' + rand() % 26;
    stack_buffer[511] = (char)0;
    
    for (int i=0; i<1023; i++)
        stack_buffer2[i] = 'A' + rand() % 26;
    stack_buffer2[1023] = (char)0;
    
    for (int i=0; i<255; i++)
        stack_struct.buffer[i] = 'A' + rand() % 26;
    stack_struct.buffer[255] = (char)0;
    stack_struct.func_ptr = &dummy_function;
    
    switch (overwrite_type) {
        case continuous: {
            int n_bytes_copy, n;
            switch (location) {
                case stack:
                    switch (pointer_type) {
                        case ret: {
                            n_bytes_copy = RET_ADDR_PTR - (void *)&stack_buffer;
	                    for (int x = 0; x < abs(n_bytes_copy); x++) {
	                    	 n = n_bytes_copy > 0 ? x+8 : -x;
	                        stack_buffer[n] = stack_buffer2[x];
	                    }
                            break;
                        }
                        case baseptr: {
                            n_bytes_copy = OLD_BP_PTR - (void *)&stack_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                stack_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case funcptr: {
                            n_bytes_copy = (void *)&stack_func_ptr - (void *)&stack_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                stack_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case structfuncptr: {
                            n_bytes_copy = get_struct_func_ptr_offset(&stack_struct);
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                stack_struct.buffer[n] = stack_buffer[x];
                            }
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(stack_jmp_buffer) == 0);
                            n_bytes_copy = (void *)&stack_jmp_buffer[0].__jmpbuf[7] - (void *)&stack_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x : -x;
                                stack_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                    }
                    break;
                case data:
                    switch (pointer_type) {
                        case funcptr: {
                            n_bytes_copy = (void *)&data_func_ptr - (void *)&data_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                data_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case structfuncptr: {
                            n_bytes_copy = get_struct_func_ptr_offset(&data_struct);
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                data_struct.buffer[n] = data_buffer[x];
                            }
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(data_jmp_buffer) == 0);
                            n_bytes_copy = (void *)&data_jmp_buffer[0].__jmpbuf[7] - (void *)&data_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                data_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;

                case bss:
                    switch (pointer_type) {
                        case funcptr: {
                            n_bytes_copy = (void *)&bss_func_ptr - (void *)&bss_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                bss_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case structfuncptr: {
                            n_bytes_copy = get_struct_func_ptr_offset(&bss_struct);
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                bss_struct.buffer[n] = bss_buffer[x];
                            }
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(bss_jmp_buffer) == 0);
                            n_bytes_copy = (void *)&bss_jmp_buffer[0].__jmpbuf[7] - (void *)&bss_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                bss_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;
                default:
                    exit(1);
            }
            break;
        }
        case jumping: {
            int offset;
            switch (location) {
                case stack:
                    switch (pointer_type) {
                        case ret: {
                            offset = RET_ADDR_PTR - (void *)&stack_buffer;
                            stack_buffer[offset] = 'A';
                            break;
                        }
                        case baseptr: {
                            offset = OLD_BP_PTR - (void *)&stack_buffer;
                            stack_buffer[offset] = 'B';
                            break;
                        }
                        case funcptr: {
                            offset = (void *)&stack_func_ptr - (void *)&stack_buffer;
                            stack_buffer[offset] = 'C';
                            break;
                        }
                        case structfuncptr: {
                            offset = get_struct_func_ptr_offset(&stack_struct);
                            stack_struct.buffer[offset] = 'D';
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(stack_jmp_buffer) == 0);
                            offset = (void *)&stack_jmp_buffer[0].__jmpbuf[7] - (void *)&stack_buffer;
                            stack_buffer[offset] = 'E';
                            break;
                        }
                    }
                    break;
                case data:
                    switch (pointer_type) {
                        case funcptr: {
                            offset = (void *)&data_func_ptr - (void *)&data_buffer;
                            data_buffer[offset] = 'F';
                            break;
                        }
                        case structfuncptr: {
                            offset = get_struct_func_ptr_offset(&data_struct);
                            data_struct.buffer[offset] = 'G';
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(data_jmp_buffer) == 0);
                            offset = (void *)&data_jmp_buffer[0].__jmpbuf[7] - (void *)&data_buffer;
                            data_buffer[offset] = 'H';
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;

                case bss:
                    switch (pointer_type) {
                        case funcptr: {
                            offset = (void *)&bss_func_ptr - (void *)&bss_buffer;
                            bss_buffer[offset] = 'I';
                            break;
                        }
                        case structfuncptr: {
                            offset = get_struct_func_ptr_offset(&bss_struct);
                            bss_struct.buffer[offset] = 'J';
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(bss_jmp_buffer) == 0);
                            offset = (void *)&bss_jmp_buffer[0].__jmpbuf[7] - (void *)&bss_buffer;
                            bss_buffer[offset] = 'K';
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;
            }
            break;
        }
    }
    // Prevent the variables from being optimized out
    dummy_glob_int = dummy_function2(stack_func_ptr);
    dummy_glob_int = dummy_glob_int + dummy_function2(&stack_jmp_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(stack_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(stack_buffer2);
    dummy_glob_int = dummy_glob_int + dummy_function4(&stack_struct);
    
    dummy_glob_int = dummy_function2(bss_func_ptr);
    dummy_glob_int = dummy_glob_int + dummy_function2(&bss_jmp_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(bss_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function4(&bss_struct);
    
    dummy_glob_int = dummy_function2(data_func_ptr);
    dummy_glob_int = dummy_glob_int + dummy_function2(&data_jmp_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(data_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function4(&data_struct);
    
    printf("%d", dummy_glob_int);
    exit(0);
}

static double PYTHAG(double a, double b) {
    double at = fabs(a), bt = fabs(b), ct, result;

    if (at > bt) {
        ct = bt / at;
        result = at * sqrt(1.0 + ct * ct);
    } else if (bt > 0.0) {
        ct = at / bt;
        result = bt * sqrt(1.0 + ct * ct);
    } else
        result = 0.0;
    return (result);
}

void svd_tst() {
#ifdef ASAN
    char stack_buffer2[1024];
    struct attackme stack_struct;
    char stack_buffer[512];
    jmp_buf stack_jmp_buffer;
    void *stack_func_ptr = &dummy_function;
#else
    void *stack_func_ptr = &dummy_function;
    jmp_buf stack_jmp_buffer;
    char stack_buffer[512];
    struct attackme stack_struct;
    char stack_buffer2[1024];
#endif

    double A[MAT_WIDTH][MAT_HEIGHT];
    double B[MAT_HEIGHT];
    double C[MAT_HEIGHT][MAT_HEIGHT];
    int flag, i, its, j, jj, k, l, nm;
    double c, f, h, s, x, y, z;
    double anorm = 0.0, g = 0.0, scale = 0.0;

    double rv1[MAT_HEIGHT];
    srand(1);

    for (int i_l = 0; i_l < MAT_WIDTH; i_l++) {
        for (int j_l = 0; j_l < MAT_HEIGHT; j_l++) {
            A[i_l][j_l] = rand();
        }
    }

    /* Householder reduction to bidiagonal form */
    for (i = 0; i < MAT_HEIGHT; i++) {
        /* left-hand reduction */
        l = i + 1;
        rv1[i] = scale * g;
        g = s = scale = 0.0;
        if (i < MAT_WIDTH) {
            for (k = i; k < MAT_WIDTH; k++) scale += fabs((double)A[k][i]);
            if (scale) {
                for (k = i; k < MAT_WIDTH; k++) {
                    A[k][i] = (double)((double)A[k][i] / scale);
                    s += ((double)A[k][i] * (double)A[k][i]);
                }
                f = (double)A[i][i];
                g = -SIGN(sqrt(s), f);
                h = f * g - s;
                A[i][i] = (double)(f - g);
                if (i != MAT_HEIGHT - 1) {
                    for (j = l; j < MAT_HEIGHT; j++) {
                        for (s = 0.0, k = i; k < MAT_WIDTH; k++) s += ((double)A[k][i] * (double)A[k][j]);
                        f = s / h;
                        for (k = i; k < MAT_WIDTH; k++) A[k][j] += (double)(f * (double)A[k][i]);
                    }
                }
                for (k = i; k < MAT_WIDTH; k++) A[k][i] = (double)((double)A[k][i] * scale);
            }
        }
        B[i] = (double)(scale * g);

        /* right-hand reduction */
        g = s = scale = 0.0;
        if (i < MAT_WIDTH && i != MAT_HEIGHT - 1) {
            for (k = l; k < MAT_HEIGHT; k++) scale += fabs((double)A[i][k]);
            if (scale) {
                for (k = l; k < MAT_HEIGHT; k++) {
                    A[i][k] = (double)((double)A[i][k] / scale);
                    s += ((double)A[i][k] * (double)A[i][k]);
                }
                f = (double)A[i][l];
                g = -SIGN(sqrt(s), f);
                h = f * g - s;
                A[i][l] = (double)(f - g);
                for (k = l; k < MAT_HEIGHT; k++) rv1[k] = (double)A[i][k] / h;
                if (i != MAT_WIDTH - 1) {
                    for (j = l; j < MAT_WIDTH; j++) {
                        for (s = 0.0, k = l; k < MAT_HEIGHT; k++) s += ((double)A[j][k] * (double)A[i][k]);
                        for (k = l; k < MAT_HEIGHT; k++) A[j][k] += (double)(s * rv1[k]);
                    }
                }
                for (k = l; k < MAT_HEIGHT; k++) A[i][k] = (double)((double)A[i][k] * scale);
            }
        }
        anorm = MAX(anorm, (fabs((double)B[i]) + fabs(rv1[i])));
    }

    /* accumulate the right-hand transformation */
    for (i = MAT_HEIGHT - 1; i >= 0; i--) {
        if (i < MAT_HEIGHT - 1) {
            if (g) {
                for (j = l; j < MAT_HEIGHT; j++) C[j][i] = (double)(((double)A[i][j] / (double)A[i][l]) / g);
                /* double division to avoid underflow */
                for (j = l; j < MAT_HEIGHT; j++) {
                    for (s = 0.0, k = l; k < MAT_HEIGHT; k++) s += ((double)A[i][k] * (double)C[k][j]);
                    for (k = l; k < MAT_HEIGHT; k++) C[k][j] += (double)(s * (double)C[k][i]);
                }
            }
            for (j = l; j < MAT_HEIGHT; j++) C[i][j] = C[j][i] = 0.0;
        }
        C[i][i] = 1.0;
        g = rv1[i];
        l = i;
    }

    // actual OOBw testing start
    
    for (int i=0; i<511; i++)
        stack_buffer[i] = 'A' + rand() % 26;
    stack_buffer[511] = (char)0;
    
    for (int i=0; i<1023; i++)
        stack_buffer2[i] = 'A' + rand() % 26;
    stack_buffer2[1023] = (char)0;
    
    for (int i=0; i<255; i++)
        stack_struct.buffer[i] = 'A' + rand() % 26;
    stack_struct.buffer[255] = (char)0;
    stack_struct.func_ptr = &dummy_function;
    
    switch (overwrite_type) {
        case continuous: {
            int n_bytes_copy, n;
            switch (location) {
                case stack:
                    switch (pointer_type) {
                        case ret: {
                            n_bytes_copy = RET_ADDR_PTR - (void *)&stack_buffer;
	                    for (int x = 0; x < abs(n_bytes_copy); x++) {
	                    	 n = n_bytes_copy > 0 ? x+8 : -x;
	                        stack_buffer[n] = stack_buffer2[x];
	                    }
                            break;
                        }
                        case baseptr: {
                            n_bytes_copy = OLD_BP_PTR - (void *)&stack_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                stack_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case funcptr: {
                            n_bytes_copy = (void *)&stack_func_ptr - (void *)&stack_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                stack_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case structfuncptr: {
                            n_bytes_copy = get_struct_func_ptr_offset(&stack_struct);
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                stack_struct.buffer[n] = stack_buffer[x];
                            }
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(stack_jmp_buffer) == 0);
                            n_bytes_copy = (void *)&stack_jmp_buffer[0].__jmpbuf[7] - (void *)&stack_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x : -x;
                                stack_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                    }
                    break;
                case data:
                    switch (pointer_type) {
                        case funcptr: {
                            n_bytes_copy = (void *)&data_func_ptr - (void *)&data_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                data_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case structfuncptr: {
                            n_bytes_copy = get_struct_func_ptr_offset(&data_struct);
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                data_struct.buffer[n] = data_buffer[x];
                            }
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(data_jmp_buffer) == 0);
                            n_bytes_copy = (void *)&data_jmp_buffer[0].__jmpbuf[7] - (void *)&data_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                data_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;

                case bss:
                    switch (pointer_type) {
                        case funcptr: {
                            n_bytes_copy = (void *)&bss_func_ptr - (void *)&bss_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                bss_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case structfuncptr: {
                            n_bytes_copy = get_struct_func_ptr_offset(&bss_struct);
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                bss_struct.buffer[n] = bss_buffer[x];
                            }
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(bss_jmp_buffer) == 0);
                            n_bytes_copy = (void *)&bss_jmp_buffer[0].__jmpbuf[7] - (void *)&bss_buffer;
                            for (int x = 0; x < abs(n_bytes_copy); x++) {
                            	 n = n_bytes_copy > 0 ? x+8 : -x;
                                bss_buffer[n] = stack_buffer2[x];
                            }
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;
                default:
                    exit(1);
            }
            break;
        }
        case jumping: {
            int offset;
            switch (location) {
                case stack:
                    switch (pointer_type) {
                        case ret: {
                            offset = RET_ADDR_PTR - (void *)&stack_buffer;
                            stack_buffer[offset] = 'A';
                            break;
                        }
                        case baseptr: {
                            offset = OLD_BP_PTR - (void *)&stack_buffer;
                            stack_buffer[offset] = 'B';
                            break;
                        }
                        case funcptr: {
                            offset = (void *)&stack_func_ptr - (void *)&stack_buffer;
                            stack_buffer[offset] = 'C';
                            break;
                        }
                        case structfuncptr: {
                            offset = get_struct_func_ptr_offset(&stack_struct);
                            stack_struct.buffer[offset] = 'D';
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(stack_jmp_buffer) == 0);
                            offset = (void *)&stack_jmp_buffer[0].__jmpbuf[7] - (void *)&stack_buffer;
                            stack_buffer[offset] = 'E';
                            break;
                        }
                    }
                    break;
                case data:
                    switch (pointer_type) {
                        case funcptr: {
                            offset = (void *)&data_func_ptr - (void *)&data_buffer;
                            data_buffer[offset] = 'F';
                            break;
                        }
                        case structfuncptr: {
                            offset = get_struct_func_ptr_offset(&data_struct);
                            data_struct.buffer[offset] = 'G';
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(data_jmp_buffer) == 0);
                            offset = (void *)&data_jmp_buffer[0].__jmpbuf[7] - (void *)&data_buffer;
                            data_buffer[offset] = 'H';
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;

                case bss:
                    switch (pointer_type) {
                        case funcptr: {
                            offset = (void *)&bss_func_ptr - (void *)&bss_buffer;
                            bss_buffer[offset] = 'I';
                            break;
                        }
                        case structfuncptr: {
                            offset = get_struct_func_ptr_offset(&bss_struct);
                            bss_struct.buffer[offset] = 'J';
                            break;
                        }
                        case longjmpptr: {
                            assert(setjmp(bss_jmp_buffer) == 0);
                            offset = (void *)&bss_jmp_buffer[0].__jmpbuf[7] - (void *)&bss_buffer;
                            bss_buffer[offset] = 'K';
                            break;
                        }
                        case ret:
                        case baseptr:
                            puts("Attack impossible\n");
                            exit(1);
                            break;
                    }
                    break;
            }
            break;
        }
    }
    // Prevent the variables from being optimized out
    dummy_glob_int = dummy_function2(stack_func_ptr);
    dummy_glob_int = dummy_glob_int + dummy_function2(&stack_jmp_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(stack_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(stack_buffer2);
    dummy_glob_int = dummy_glob_int + dummy_function4(&stack_struct);
    
    dummy_glob_int = dummy_function2(bss_func_ptr);
    dummy_glob_int = dummy_glob_int + dummy_function2(&bss_jmp_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(bss_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function4(&bss_struct);
    
    dummy_glob_int = dummy_function2(data_func_ptr);
    dummy_glob_int = dummy_glob_int + dummy_function2(&data_jmp_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function3(data_buffer);
    dummy_glob_int = dummy_glob_int + dummy_function4(&data_struct);
    
    printf("%d", dummy_glob_int);
    // actual OOBw testing end

    /* accumulate the left-hand transformation */
    for (i = MAT_HEIGHT - 1; i >= 0; i--) {
        l = i + 1;
        g = (double)B[i];
        if (i < MAT_HEIGHT - 1)
            for (j = l; j < MAT_HEIGHT; j++) A[i][j] = 0.0;
        if (g) {
            g = 1.0 / g;
            if (i != MAT_HEIGHT - 1) {
                for (j = l; j < MAT_HEIGHT; j++) {
                    for (s = 0.0, k = l; k < MAT_WIDTH; k++) s += ((double)A[k][i] * (double)A[k][j]);
                    f = (s / (double)A[i][i]) * g;
                    for (k = i; k < MAT_WIDTH; k++) A[k][j] += (double)(f * (double)A[k][i]);
                }
            }
            for (j = i; j < MAT_WIDTH; j++) A[j][i] = (double)((double)A[j][i] * g);
        } else {
            for (j = i; j < MAT_WIDTH; j++) A[j][i] = 0.0;
        }
        ++A[i][i];
    }

    /* diagonalize the bidiagonal form */
    for (k = MAT_HEIGHT - 1; k >= 0; k--) { /* loop over singular values */
        for (its = 0; its < 30; its++) {    /* loop over allowed iterations */
            flag = 1;
            for (l = k; l >= 0; l--) { /* test for splitting */
                nm = l - 1;
                if (fabs(rv1[l]) + anorm == anorm) {
                    flag = 0;
                    break;
                }
                if (fabs((double)B[nm]) + anorm == anorm)
                    break;
            }
            if (flag) {
                c = 0.0;
                s = 1.0;
                for (i = l; i <= k; i++) {
                    f = s * rv1[i];
                    if (fabs(f) + anorm != anorm) {
                        g = (double)B[i];
                        h = PYTHAG(f, g);
                        B[i] = (double)h;
                        h = 1.0 / h;
                        c = g * h;
                        s = (-f * h);
                        for (j = 0; j < MAT_WIDTH; j++) {
                            y = (double)A[j][nm];
                            z = (double)A[j][i];
                            A[j][nm] = (double)(y * c + z * s);
                            A[j][i] = (double)(z * c - y * s);
                        }
                    }
                }
            }
            z = (double)B[k];
            if (l == k) {      /* convergence */
                if (z < 0.0) { /* make singular value nonnegative */
                    B[k] = (double)(-z);
                    for (j = 0; j < MAT_HEIGHT; j++) C[j][k] = (-C[j][k]);
                }
                break;
            }
            if (its >= 30) {
                fprintf(stderr, "No convergence after 30,000! iterations \n");
                return;
            }

            /* shift from bottom 2 x 2 minor */
            x = (double)B[l];
            nm = k - 1;
            y = (double)B[nm];
            g = rv1[nm];
            h = rv1[k];
            f = ((y - z) * (y + z) + (g - h) * (g + h)) / (2.0 * h * y);
            g = PYTHAG(f, 1.0);
            f = ((x - z) * (x + z) + h * ((y / (f + SIGN(g, f))) - h)) / x;

            /* next QR transformation */
            c = s = 1.0;
            for (j = l; j <= nm; j++) {
                i = j + 1;
                g = rv1[i];
                y = (double)B[i];
                h = s * g;
                g = c * g;
                z = PYTHAG(f, h);
                rv1[j] = z;
                c = f / z;
                s = h / z;
                f = x * c + g * s;
                g = g * c - x * s;
                h = y * s;
                y = y * c;
                for (jj = 0; jj < MAT_HEIGHT; jj++) {
                    x = (double)C[jj][j];
                    z = (double)C[jj][i];
                    C[jj][j] = (double)(x * c + z * s);
                    C[jj][i] = (double)(z * c - x * s);
                }
                z = PYTHAG(f, h);
                B[j] = (double)z;
                if (z) {
                    z = 1.0 / z;
                    c = f * z;
                    s = h * z;
                }
                f = (c * g) + (s * y);
                x = (c * y) - (s * g);
                for (jj = 0; jj < MAT_WIDTH; jj++) {
                    y = (double)A[jj][j];
                    z = (double)A[jj][i];
                    A[jj][j] = (double)(y * c + z * s);
                    A[jj][i] = (double)(z * c - y * s);
                }
            }
            rv1[l] = 0.0;
            rv1[k] = f;
            B[k] = (double)x;
        }
    }

    printf("svd done\n");
    exit(0);
}

int main(int argc, char **argv) {
    int option_char, i;
    char *ptr_arg, *ctx_arg;

    while ((option_char = getopt(argc, argv, "t:l:c:p:")) != -1) {
        switch (option_char) {
            case 't':
                if (strcmp(optarg, "continuous") == 0) {
                    overwrite_type = continuous;
                } else if (strcmp(optarg, "jumping") == 0) {
                    overwrite_type = jumping;
                } else {
                    puts("Unknown option for argument -t\n");
                    exit(1);
                }
                break;
            case 'l':
                if (strcmp(optarg, "stack") == 0) {
                    location = stack;
                } else if (strcmp(optarg, "data") == 0) {
                    location = data;
                } else if (strcmp(optarg, "bss") == 0) {
                    location = bss;
                } else {
                    puts("Unknown option for location\n");
                    exit(1);
                }
                break;
            case 'c':
                if (strcmp(optarg, "iso") == 0) {
                    context = iso;
                } else if (strcmp(optarg, "svd") == 0) {
                    context = svd;
                } else {
                    puts("Unknown option for context\n");
                    exit(1);
                }
                break;
            case 'p':
                if (strcmp(optarg, "ret") == 0) {
                    pointer_type = ret;
                } else if (strcmp(optarg, "baseptr") == 0) {
                    pointer_type = baseptr;
                } else if (strcmp(optarg, "funcptr") == 0) {
                    pointer_type = funcptr;
                } else if (strcmp(optarg, "structfuncptr") == 0) {
                    pointer_type = structfuncptr;
                } else if (strcmp(optarg, "longjmp") == 0) {
                    pointer_type = longjmpptr;
                } else {
                    puts("Unknown option for pointer\n");
                    exit(1);
                }
                break;
            default:
                fprintf(stderr, "Error: Unknown command option \"%s\"\n", optarg);
                exit(1);
                break;
        }
    }
    if (context == iso) {
        iso_tst();
    } else {
        svd_tst();
    }
}
