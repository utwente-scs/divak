#include <setjmp.h>
#include <stdlib.h>

struct attackme {
    char buffer[256];
    int (*func_ptr)(const char *);
};

int dummy_function(const char *str);
int dummy_function2(jmp_buf* jump_buf);
int dummy_function3(char* buf);
int dummy_function4(struct attackme* stack_struct);
int get_struct_func_ptr_offset(struct attackme* argstruct);
