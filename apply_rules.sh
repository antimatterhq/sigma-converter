#!/bin/bash
# Apply DSL command to all JSON rule files in output directory

OUTPUT_DIR="${1:-output}"

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Directory '$OUTPUT_DIR' does not exist"
    exit 1
fi

echo "Applying DSL to rules in: $OUTPUT_DIR"
echo ""

# Count files
total=$(find "$OUTPUT_DIR" -name "*.json" | wc -l | tr -d ' ')
echo "Found $total JSON file(s)"
echo ""

# Loop through all JSON files
count=0
failed=0

for file in "$OUTPUT_DIR"/*.json; do
    if [ -f "$file" ]; then
        count=$((count + 1))
        filename=$(basename "$file")
        echo "[$count/$total] Applying: $filename"
        
        if dsl apply "$file"; then
            echo "  ✓ Success"
        else
            echo "  ✗ Failed"
            failed=$((failed + 1))
        fi
        echo ""
    fi
done

echo "Summary:"
echo "  Total:   $count"
echo "  Success: $((count - failed))"
echo "  Failed:  $failed"

exit $failed

