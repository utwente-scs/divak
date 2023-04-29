cmake_minimum_required(VERSION 3.15)

project(gzip LANGUAGES C)

    add_compile_options("-flegacy-pass-manager" "SHELL:-Xclang -load" "SHELL:-Xclang /home/linus/Desktop/thesis-code-test-new/llvmPass/build/OOBCollector/libOOBCollector.so")


add_executable(
    ${PROJECT_NAME} 

    bits.c
    crypt.c
    deflate.c
    getopt.c
    gzip.c
    inflate.c
    lzw.c
    lzw.h
    match.S
    trees.c
    unlzh.c
    unlzw.c
    unpack.c
    unzip.c
    util.c
    zip.c
)

set_property(TARGET ${PROJECT_NAME} PROPERTY C_STANDARD 90)
