#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// SVD implementation from https://github.com/kaushikb258/SVD_C
#define PRECISION1 32768
#define PRECISION2 16384
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define SIGN(a, b) ((b) >= 0.0 ? fabs(a) : -fabs(a))
#define MAXINT 2147483647
#define ASCII_TEXT_BORDER_WIDTH 4
#define MAXHIST 100
#define STEP0 0.01
#define FORWARD 1
#define BACKWARD -1
#define PROJ_DIM 5
#define True 1
#define False 0

typedef struct {
    float x, y, z;
} fcoords;

typedef struct {
    long x, y, z;
} lcoords;

typedef struct {
    int x, y, z;
} icoords;

typedef struct {
    float min, max;
} lims;

/* grand tour history */
typedef struct hist_rec {
    struct hist_rec *prev, *next;
    float *basis[3];
    int pos;
} hist_rec;

static const int MAT_WIDTH = 4;
static const int MAT_HEIGHT = 4;
