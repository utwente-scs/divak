# Divak: Non-invasive Characterization of Out-of-bounds Write Vulnerabilities


All instructions have been tested to work on a fresh Ubuntu 20.04 installation.

## Setup
```
git clone https://gitfront.io/r/user-9165005/KbAJ1tujK62X/divak-noninvasive-oobw-characterization.git
cd noninvasive-oobw-characterization
export WORKDIR=${PWD}
./setup.sh
```
The setup script builds S2E from source so this takes quite some time (around an hour).

## Running
We'll use the ancient version of gzip contained in ```example/gzip```, containing CVE-2001-1228, as an example.

First of all, make sure that the environment variable `WORKDIR` is set to the root of this repository.
The `CMakeLists.txt` required for building gzip is already in `example/gzip` and modified to use our analysis pass.

Now, build gzip as follows:
```
cd ${WORKDIR}/example/gzip
mkdir build && cd build
CC=${WORKDIR}/clang-13.0.1/bin/clang CFLAGS="-g3 -fno-optimize-sibling-calls -fno-omit-frame-pointer -gdwarf-4" cmake ../src
cmake --build .
```

Now we have the gzip binary at `example/gzip/build/gzip` and multiple JSON files with IR analysis results in the same directory.
Next, we run our static analysis.

```
cd ${WORKDIR}/staticAnalysis
source ${WORKDIR}/staticAnalysis/venv/bin/activate && python3 main.py --elf=${WORKDIR}/example/gzip/build/gzip --json_dir=${WORKDIR}/example/gzip/build/
```

This yields an additional file with the aggregated analysis results at `example/gzip/pass-res-aug.json`.
Now, we initialize the S2E project in preparation for the dynamic analysis.

```
export PROG_PATH=${WORKDIR}/example/gzip/build/gzip
export STATIC_ANALYSIS_PATH=${WORKDIR}/example/gzip/build/pass-res-aug.json
export S2E_DIR=${WORKDIR}/s2e/
export S2E_ENV_DIR=${WORKDIR}/s2e-env/
export RESULT_DIR=${WORKDIR}/example/gzip/
${WORKDIR}/run.sh init
```

This creates a new s2e project at `s2e/projects/gzip`, configured to ingest the binary and static analysis results.
As a last step before launching the dynamic analysis, we need to configure the project to pass the command line argument to gzip that triggers CVE-2001-1228. To do this, we edit `s2e/projects/gzip/bootstrap.sh` by replacing the line
```
S2E_SYM_ARGS="" LD_PRELOAD="${S2E_SO}" "${TARGET}" "$@" > /dev/null 2> /dev/null
```
with 
```
S2E_SYM_ARGS="" LD_PRELOAD="${S2E_SO}" "${TARGET}" $(printf 'A%.0s' {1..1200}) > /dev/null 2> /dev/null
```

Now, we can finally start the dynamic analysis by invoking
```
${WORKDIR}/run.sh run
```

This places the results with the discovered OOB writes at `example/gzip/dynamic-analysis-results.json`


### Running with other programs
The procedure for running other programs is effectively the same as for gzip. 
To run our analysis pass during compilation, add the following line to `CMakeLists.txt` right after the `project()` command:
```
add_compile_options("-flegacy-pass-manager" "SHELL:-Xclang -load" "SHELL:-Xclang <path-to-workdir>/llvmPass/build/OOBCollector/libOOBCollector.so")
```

If the program requires shared libraries that are not present in the QEMU image of S2E, you will need to modify the S2E project's `bootstrap.sh` to use s2eget for loading these libraries into the VM before the program is launched.

The running time of some programs benefits from setting the KLEE argument `--use-expr-simplifier=false` in the `s2e-config.lua` located in the S2E project's directory.

