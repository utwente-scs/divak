#include "dummy.h"

int dummy_function(const char *str) { return 0; }
int dummy_function2(jmp_buf* jump_buf) { return rand(); }
int dummy_function3(char* buf) { return rand(); }
int dummy_function4(struct attackme* stack_struct) { return rand(); }
int get_struct_func_ptr_offset(struct attackme* argstruct) { return (void *)&argstruct->func_ptr - (void *)&argstruct->buffer; }
