#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

set -e
# set 1 to debug the script
VERBOSE=0

DPA_HEADER_INC_FLAGS="$1"
HOST_COMPILE_EXTRA_FLAGS=$2
DEVICE_COMPILE_EXTRA_FLAGS=$3
DPACC_CORE_MODEL_FLAG=$4
BUILD_OPTION=$5
BUILD_OUT_DIR=$6

if [ ${VERBOSE} -eq 1 ]
then
  echo "running script with: "
  echo "  DPA_HEADER_INC_FLAGS=${DPA_HEADER_INC_FLAGS}"
  echo "  HOST_COMPILE_EXTRA_FLAGS=${HOST_COMPILE_EXTRA_FLAGS}"
  echo "  DEVICE_COMPILE_EXTRA_FLAGS=${DEVICE_COMPILE_EXTRA_FLAGS}"
  echo "  DPACC_CORE_MODEL_FLAG=${DPACC_CORE_MODEL_FLAG}"
  echo "  BUILD_OPTION=${BUILD_OPTION}"
  echo "  BUILD_OUT_DIR=${BUILD_OUT_DIR}"
fi

# Compiler options
## -Wno-deprecated-declarations: not to warn when functions, variables, types, or other code elements marked as deprecated (using __attribute__((deprecated)) in GCC or similar mechanisms) are used.
## -Werror: all warnings are treated as errors, causing compilation to fail if any warning is triggered.
## -Wall: enable a broad set of common warnings that may not be enabled by default.
## -Wextra: enables extra warnings that are not covered by -Wall, giving an even more thorough warning coverage.
WARNING_FLAGS="-Wno-deprecated-declarations -Werror -Wall -Wextra"

## -fPIC: generate Position Independent Code, which is necessary for creating shared libraries that can be loaded at arbitrary memory addresses without modification.
HOST_COMPILE_FLAGS="${WARNING_FLAGS} -fPIC -DFLEXIO_ALLOW_EXPERIMENTAL_API ${HOST_COMPILE_EXTRA_FLAGS}"

## -ffreestanding: assume a freestanding environment—one where standard libraries and startup code are not guaranteed to exist.
##                 Compiler does not make assumptions about library functions (like main, printf, etc.), allowing low-level code to be built without dependencies on external libraries.
## -mcmodel: "medium, any address", code and data can be located anywhere in the address space, and the compiler generates instructions that work regardless of final code and data placement.
## -Wdouble-promotion: warn when a float is implicitly promoted to double in arithmetic operations, function calls.
## -MMD -MT <target_name>:
## -MMD: The -MMD option tells the compiler to generate dependencies in Makefile format for the specified source file.
##       The output is typically a .d file listing the source file and its local dependencies.
## -MT <target_name>: The -MT option allows specification of the "target" name used in the generated dependency file.
DEVICE_COMPILE_FLAGS="${WARNING_FLAGS} -ffreestanding -mcmodel=medany -O0 -Wdouble-promotion -DFLEXIO_DEV_ALLOW_EXPERIMENTAL_API ${DEVICE_COMPILE_EXTRA_FLAGS} -mllvm -inline-threshold=1000000 -mllvm -inlinehint-threshold=1000000 -mllvm -lto-embed-bitcode=optimized"

case "${BUILD_OPTION}" in
  "program") # Build out DPA DPU-ARM archive with DPA-RISCV program from source code
     DPA_DEV_LIBS_LINK_FLAGS=${7}
     DPA_APP_NAME=${8}
     OUTPUT_ARCHIVE_NAME=${9}
     DPA_SOURCE_FILES="${@:10}"
     DEVICE_COMPILE_FLAGS="-MMD -MT ${OUTPUT_ARCHIVE_NAME} ${DEVICE_COMPILE_FLAGS}"

     if [ ${VERBOSE} -eq 1 ]
     then
       echo "  DPA_DEV_LIBS_LINK_FLAGS=${DPA_DEV_LIBS_LINK_FLAGS}"
       echo "  DPA_APP_NAME=${DPA_APP_NAME}"
       echo "  OUTPUT_ARCHIVE_NAME=${OUTPUT_ARCHIVE_NAME}"
       echo "  DPA_SOURCE_FILES=${DPA_SOURCE_FILES}"
       echo "  DEVICE_COMPILE_FLAGS=${DEVICE_COMPILE_FLAGS}"
     fi

     dpacc ${DPA_SOURCE_FILES} -o "${OUTPUT_ARCHIVE_NAME}" -mcpu=${DPACC_CORE_MODEL_FLAG} -hostcc=gcc -hostcc-options="${HOST_COMPILE_FLAGS}" \
     --devicecc-options="${DEVICE_COMPILE_FLAGS}" ${DPA_HEADER_INC_FLAGS} -device-libs="${DPA_DEV_LIBS_LINK_FLAGS}" --app-name=${DPA_APP_NAME} -flto -disable-asm-checks --keep-dir ${BUILD_OUT_DIR}

     ;;

  "src_obj") # Build out DPA DPU-ARM object file with DPA-RISCV program from source code
     OUTPUT_OBJECT_FILE=${7}
     DPA_SOURCE_FILE=${8}
     DEVICE_COMPILE_FLAGS="-MMD -MT ${OUTPUT_OBJECT_FILE} ${DEVICE_COMPILE_FLAGS}"

     if [ ${VERBOSE} -eq 1 ]
     then
       echo "  OUTPUT_OBJECT_FILE=${OUTPUT_OBJECT_FILE}"
       echo "  DPA_SOURCE_FILE=${DPA_SOURCE_FILE}"
       echo "  DEVICE_COMPILE_FLAGS=${DEVICE_COMPILE_FLAGS}"
     fi

     dpacc ${DPA_SOURCE_FILE} -o "${OUTPUT_OBJECT_FILE}" -c -mcpu=${DPACC_CORE_MODEL_FLAG} -hostcc=gcc -hostcc-options="${HOST_COMPILE_FLAGS}" \
     --devicecc-options="${DEVICE_COMPILE_FLAGS}" ${DPA_HEADER_INC_FLAGS} -flto -disable-asm-checks --keep-dir ${BUILD_OUT_DIR}

     ;;

  "host_obj") # Build out DPA DPU-ARM object with DPA-RISCV program from src_obj
     DPA_DEV_LIBS_LINK_FLAGS=${7}
     DPA_APP_NAME=${8}
     OUTPUT_HOST_OBJ=${9}
     DPA_SOURCE_OBJECTS="${@:10}"

     if [ ${VERBOSE} -eq 1 ]
     then
       echo "  DPA_DEV_LIBS_LINK_FLAGS=${DPA_DEV_LIBS_LINK_FLAGS}"
       echo "  DPA_APP_NAME=${DPA_APP_NAME}"
       echo "  OUTPUT_HOST_OBJ=${OUTPUT_HOST_OBJ}"
       echo "  DPA_SOURCE_OBJECTS=${DPA_SOURCE_OBJECTS}"
     fi

    INTERMEDIATE_ARCHIVE_NAME="intermediate_dpa_host_archive.a"
    dpacc ${DPA_SOURCE_OBJECTS} -o "${BUILD_OUT_DIR}/${INTERMEDIATE_ARCHIVE_NAME}" -mcpu=${DPACC_CORE_MODEL_FLAG} -hostcc=gcc -hostcc-options="${HOST_COMPILE_FLAGS}" \
    --devicecc-options="${DEVICE_COMPILE_FLAGS}" ${DPA_HEADER_INC_FLAGS} -device-libs="${DPA_DEV_LIBS_LINK_FLAGS}" --app-name=${DPA_APP_NAME} -flto -disable-asm-checks

    pushd ${BUILD_OUT_DIR} > /dev/null
    ar x ${INTERMEDIATE_ARCHIVE_NAME}
    popd > /dev/null
    mv "${BUILD_OUT_DIR}/hostStubs.o" "${OUTPUT_HOST_OBJ}"

   ;;

  "host_shared_lib") # Build out DPA DPU-ARM shared library with DPA-RISCV program from src_obj
     DPA_APP_NAME=${7}
     OUTPUT_HOST_SHARED_LIB=${8}
     DPA_SOURCE_OBJECTS="${@:9}"

     if [ ${VERBOSE} -eq 1 ]
     then
       echo "  DPA_APP_NAME=${DPA_APP_NAME}"
       echo "  OUTPUT_HOST_SHARED_LIB=${OUTPUT_HOST_SHARED_LIB}"
       echo "  DPA_SOURCE_OBJECTS=${DPA_SOURCE_OBJECTS}"
     fi

    dpacc ${DPA_SOURCE_OBJECTS} -o ${OUTPUT_HOST_SHARED_LIB}.so -mcpu=${DPACC_CORE_MODEL_FLAG} -hostcc=gcc -hostcc-options="${HOST_COMPILE_FLAGS}" \
    --devicecc-options="${DEVICE_COMPILE_FLAGS}" ${DPA_HEADER_INC_FLAGS} -device-libs=' ' --app-name=${DPA_APP_NAME} -flto -disable-asm-checks -shared

    ;;

  "host_dev_libs") # Build out DPA DPU-ARM & DPA-RISCV libraries
     PROJECT_BUILD_ROOT=${7}
     OUTPUT_LIB_NAME=${8}
     DPA_SOURCE_OBJECTS="${@:9}"

     if [ ${VERBOSE} -eq 1 ]
     then
       echo "  PROJECT_BUILD_ROOT=${PROJECT_BUILD_ROOT}"
       echo "  OUTPUT_LIB_NAME=${OUTPUT_LIB_NAME}"
       echo "  DPA_SOURCE_OBJECTS=${DPA_SOURCE_OBJECTS}"
     fi

    HOST_ARCHIVE_NAME="${OUTPUT_LIB_NAME}_host.a"
    DEVICE_ARCHIVE_NAME="${OUTPUT_LIB_NAME}_device.a"
    dpacc -gen-libs ${DPA_SOURCE_OBJECTS} -o "${BUILD_OUT_DIR}/${OUTPUT_LIB_NAME}" -mcpu=${DPACC_CORE_MODEL_FLAG} -hostcc=gcc -hostcc-options="${HOST_COMPILE_FLAGS}" \
    --devicecc-options="${DEVICE_COMPILE_FLAGS}" ${DPA_HEADER_INC_FLAGS} -flto -disable-asm-checks --keep-dir ${BUILD_OUT_DIR}

    pushd ${BUILD_OUT_DIR} > /dev/null
    ar x ${HOST_ARCHIVE_NAME}
    popd > /dev/null
    mv "${BUILD_OUT_DIR}/${DEVICE_ARCHIVE_NAME}" "${PROJECT_BUILD_ROOT}/libs/${OUTPUT_LIB_NAME}.a"

    ;;

   *) # Illegal mode
    echo "Illegal mode"
esac
