#!/bin/bash
# build_autorun_embedded.sh
# Convert binary files to kernel linkable objects using objcopy

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/autorun_embedded"
INPUT_DIR="${SCRIPT_DIR}/autorun"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Detect cross-compile prefix
if [ -n "${CROSS_COMPILE}" ]; then
    OBJCOPY="${CROSS_COMPILE}objcopy"
elif command -v aarch64-linux-gnu-objcopy &> /dev/null; then
    OBJCOPY="aarch64-linux-gnu-objcopy"
elif command -v aarch64-linux-android-objcopy &> /dev/null; then
    OBJCOPY="aarch64-linux-android-objcopy"
else
    echo "Error: Cannot find objcopy. Set CROSS_COMPILE or install aarch64-linux-gnu-binutils"
    exit 1
fi

echo "Using objcopy: ${OBJCOPY}"
echo "Input directory: ${INPUT_DIR}"
echo "Output directory: ${OUTPUT_DIR}"

# Check if input files exist
if [ ! -f "${INPUT_DIR}/autorun" ]; then
    echo "Error: ${INPUT_DIR}/autorun not found"
    exit 1
fi

if [ ! -f "${INPUT_DIR}/Autorun_HTML.zip" ]; then
    echo "Error: ${INPUT_DIR}/Autorun_HTML.zip not found"
    exit 1
fi

# Convert autorun ELF
echo "Converting autorun ELF..."
${OBJCOPY} -I binary -O elf64-littleaarch64 -B aarch64 \
    -R .note \
    "${INPUT_DIR}/autorun" "${OUTPUT_DIR}/autorun_bin.o"

# Convert Autorun_HTML.zip
echo "Converting Autorun_HTML.zip..."
${OBJCOPY} -I binary -O elf64-littleaarch64 -B aarch64 \
    -R .note \
    "${INPUT_DIR}/Autorun_HTML.zip" "${OUTPUT_DIR}/Autorun_HTML_zip.o"

echo ""
echo "Build complete! Generated files:"
ls -la "${OUTPUT_DIR}/"

echo ""
echo "Symbols generated:"
${OBJCOPY} -t "${OUTPUT_DIR}/autorun_bin.o" | head -5
${OBJCOPY} -t "${OUTPUT_DIR}/Autorun_HTML_zip.o" | head -5
