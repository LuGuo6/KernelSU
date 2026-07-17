#!/bin/bash
# prepare_autorun.sh - Automatically prepare autorun files for kernel embedding
# Supports autorun.conf for specifying target paths and permissions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTORUN_DIR="${SCRIPT_DIR}/autorun"
OUTPUT_DIR="${SCRIPT_DIR}/autorun_embedded"
CONFIG_FILE="${AUTORUN_DIR}/autorun.conf"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Detect objcopy
if command -v llvm-objcopy &> /dev/null; then
    OBJCOPY="llvm-objcopy"
elif [ -n "${CROSS_COMPILE}" ]; then
    OBJCOPY="${CROSS_COMPILE}objcopy"
elif command -v aarch64-linux-gnu-objcopy &> /dev/null; then
    OBJCOPY="aarch64-linux-gnu-objcopy"
else
    echo "Error: Cannot find objcopy. Set CROSS_COMPILE or install llvm-objcopy"
    exit 1
fi

echo "Using objcopy: ${OBJCOPY}"
echo "Input directory: ${AUTORUN_DIR}"
echo "Output directory: ${OUTPUT_DIR}"

# Check if autorun directory exists
if [ ! -d "${AUTORUN_DIR}" ]; then
    echo "Error: ${AUTORUN_DIR} directory not found"
    exit 1
fi

# Initialize output files
MK_FILE="${OUTPUT_DIR}/AUTORUN_SOURCES.mk"
H_FILE="${OUTPUT_DIR}/autorun_config.h"

echo "# Auto-generated from autorun/ directory - DO NOT EDIT" > "${MK_FILE}"
echo "" >> "${MK_FILE}"

echo "// Auto-generated from autorun/ directory - DO NOT EDIT" > "${H_FILE}"
echo "#ifndef AUTORUN_CONFIG_H" >> "${H_FILE}"
echo "#define AUTORUN_CONFIG_H" >> "${H_FILE}"
echo "" >> "${H_FILE}"

ENTRY_COUNT=0

# Function to process a single file
process_file() {
    local src_file="$1"
    local target_path="$2"
    local mode="$3"
    local filename=$(basename "${src_file}")

    # Generate symbol name (replace non-alphanumeric with _)
    local symbol=$(echo "${filename}" | sed 's/[^a-zA-Z0-9]/_/g')

    echo "Processing: ${filename} -> ${target_path} (mode: ${mode})"

    # Run objcopy
    ${OBJCOPY} -I binary -O elf64-littleaarch64 -B aarch64 \
        -R .note \
        "${src_file}" "${OUTPUT_DIR}/${symbol}.o"

    # Create .cmd file for kbuild dependency tracking
    touch "${OUTPUT_DIR}/.${symbol}.o.cmd"

    # Add to Makefile
    echo "kernelsu-objs += autorun_embedded/${symbol}.o" >> "${MK_FILE}"

    # Add extern declaration to header
    echo "extern char __start_${symbol}[];" >> "${H_FILE}"
    echo "extern char __end_${symbol}[];" >> "${H_FILE}"

    ENTRY_COUNT=$((ENTRY_COUNT + 1))
}

# Process files based on config or auto-discover
if [ -f "${CONFIG_FILE}" ]; then
    echo "Using config file: ${CONFIG_FILE}"
    echo ""

    # Process each line in config file
    while IFS=' ' read -r src_file target_path mode || [ -n "${src_file}" ]; do
        # Skip comments and empty lines
        [[ "${src_file}" == \#* ]] && continue
        [ -z "${src_file}" ] && continue

        src_path="${AUTORUN_DIR}/${src_file}"

        if [ ! -f "${src_path}" ]; then
            echo "Warning: ${src_path} not found, skipping"
            continue
        fi

        process_file "${src_path}" "${target_path}" "${mode}"
    done < "${CONFIG_FILE}"
else
    echo "No config file found, processing all files with default target"
    echo ""

    # Fallback: process all files with default target path
    for file in "${AUTORUN_DIR}"/*; do
        [ -f "${file}" ] || continue
        filename=$(basename "${file}")

        # Skip source files and config files
        [[ "${filename}" == *.c ]] && continue
        [[ "${filename}" == *.conf ]] && continue

        target="/data/adb/微微微/${filename}"
        process_file "${file}" "${target}" "0644"
    done
fi

if [ ${ENTRY_COUNT} -eq 0 ]; then
    echo "No binary files to process, generating empty placeholder files"
    
    # Generate empty placeholder header - NO array, only count macro
    cat > "${H_FILE}" << 'EOF'
// Auto-generated from autorun/ directory - DO NOT EDIT
// No files to embed
#ifndef AUTORUN_CONFIG_H
#define AUTORUN_CONFIG_H

// No files configured for embedding
#define AUTORUN_ENTRIES_COUNT 0

#endif /* AUTORUN_CONFIG_H */
EOF

    # Generate empty Makefile fragment
    echo "# Auto-generated - no files to embed" > "${MK_FILE}"
    
    echo "Generated empty placeholder files"
    ls -la "${OUTPUT_DIR}/"
    exit 0
fi

# Generate struct definition in header with entry count
cat >> "${H_FILE}" << EOF

// Number of entries
#define AUTORUN_ENTRIES_COUNT ${ENTRY_COUNT}

EOF

cat >> "${H_FILE}" << 'EOF'

// Autorun entry structure
struct autorun_entry {
    const char *start;
    const char *end;
    const char *target_path;
    unsigned int mode;
};

// Autorun entries array
static const struct autorun_entry autorun_entries[] = {
EOF

# Add entries from config or default
if [ -f "${CONFIG_FILE}" ]; then
    while IFS=' ' read -r src_file target_path mode || [ -n "${src_file}" ]; do
        [[ "${src_file}" == \#* ]] && continue
        [ -z "${src_file}" ] && continue
        filename=$(basename "${src_file}")
        symbol=$(echo "${filename}" | sed 's/[^a-zA-Z0-9]/_/g')
        echo "    {__start_${symbol}, __end_${symbol}, \"${target_path}\", ${mode}}," >> "${H_FILE}"
    done < "${CONFIG_FILE}"
else
    for file in "${AUTORUN_DIR}"/*; do
        [ -f "${file}" ] || continue
        filename=$(basename "${file}")
        [[ "${filename}" == *.c ]] && continue
        [[ "${filename}" == *.conf ]] && continue
        symbol=$(echo "${filename}" | sed 's/[^a-zA-Z0-9]/_/g')
        echo "    {__start_${symbol}, __end_${symbol}, \"/data/adb/微微微/${filename}\", 0644}," >> "${H_FILE}"
    done
fi

echo "};" >> "${H_FILE}"
echo "" >> "${H_FILE}"
echo "#endif /* AUTORUN_CONFIG_H */" >> "${H_FILE}"

echo ""
echo "=== Autorun preparation complete ==="
echo "Processed ${ENTRY_COUNT} file(s)"
echo ""
echo "Generated files:"
ls -la "${OUTPUT_DIR}/"
