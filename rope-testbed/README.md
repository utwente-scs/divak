Build as follows:
```
clang -fno-stack-protector -c -o dummy.o ../source/dummy.c
clang -fno-stack-protector -lm -o rope ../source/rope.c dummy.o
```

Run with `./rope -t <type> -l <location> -c <context> -p <pointer>` where
```
type ∈ {continuous, jumping}
location ∈ {stack, data, bss}
context ∈ {iso, svd}
pointer ∈ {ret, baseptr, funcptr, structfuncptr, longjmpptr}
```

A more thorough description is available in the Evaluation chapter of the thesis.