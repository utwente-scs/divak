#! /bin/bash

set -e

function new_s2e_project {
    source ${WORKDIR}/s2e-env/venv/bin/activate && source ${WORKDIR}/s2e/s2e_activate
    s2e new_project -i debian-9.2.1-x86_64 ${PROG_PATH}
    cd ${S2E_DIR}/projects/$(basename "${PROG_PATH}")

    # disable unwanted plugins
    sed -i 's/add_plugin("WebServiceInterface")/--add_plugin("WebServiceInterface")/' s2e-config.lua
    sed -i 's/add_plugin("LuaBindings")/--add_plugin("LuaBindings")/' s2e-config.lua
    sed -i 's/add_plugin("LuaCoreEvents")/--add_plugin("LuaCoreEvents")/' s2e-config.lua
    sed -i 's/add_plugin("TranslationBlockCoverage")/--add_plugin("TranslationBlockCoverage")/' s2e-config.lua
    sed -i 's/add_plugin("TestCaseGenerator")/--add_plugin("TestCaseGenerator")/' s2e-config.lua

    echo -e "
add_plugin(\"FunctionMonitor\")

add_plugin(\"OOBTracker\")

pluginsConfig.OOBTracker = {
  resultsPath = \"${RESULT_DIR}/dynamic-analysis-results.json\",
  statsPath = \"${RESULT_DIR}/dynamic-analysis-stats.json\",
}

add_plugin(\"MemoryTracker\")

pluginsConfig.MemoryTracker = {
  auxiliaryDataPath = \"${STATIC_ANALYSIS_PATH}\",
}

add_plugin(\"OOBAnalyzer\")

" >> s2e-config.lua

}

function run_s2e {
  cd ${WORKDIR}/s2e/projects/$(basename "${PROG_PATH}")
  source ${WORKDIR}/s2e-env/venv/bin/activate && source ${WORKDIR}/s2e/s2e_activate
  ./launch-s2e.sh
}

if [[ -z "${PROG_PATH}" ]]; then
  echo "ERROR: PROG_PATH is not set"
  exit 1
fi

if [[ -z "${STATIC_ANALYSIS_PATH}" ]]; then
  echo "ERROR: STATIC_ANALYSIS_PATH is not set"
  exit 1
fi

if [[ -z "${WORKDIR}" ]]; then
  echo "ERROR: WORKDIR is not set"
  exit 1
fi

if [[ -z "${RESULT_DIR}" ]]; then
  RESULT_DIR="$(dirname "${PROG_PATH}")"
  echo "WARNING: RESULT_DIR is not set, using ${RESULT_DIR}"
fi

if [ "$1" == "init" ]; then
  new_s2e_project
elif [ "$1" == "run" ]; then
  run_s2e
else
  echo "Available commands: init, run"
  echo "Expected environment variables: PROG_PATH, STATIC_ANALYSIS_PATH, WORKDIR, RESULT_DIR"
  exit 1
fi
