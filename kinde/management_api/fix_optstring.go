// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
)

// This tool patches the generated oas_json_gen.go file to fix OptString.Decode()
// null handling until ogen fixes this upstream.
// See: https://github.com/ogen-go/ogen/issues/XXX

const (
	targetFile = "oas_json_gen.go"

	// The buggy generated code pattern
	oldPattern = `func \(o \*OptString\) Decode\(d \*jx\.Decoder\) error \{
	if o == nil \{
		return errors\.New\("invalid: unable to decode OptString to nil"\)
	\}
	o\.Set = true
	v, err := d\.Str\(\)`

	// The fixed code
	newCode = `func (o *OptString) Decode(d *jx.Decoder) error {
	if o == nil {
		return errors.New("invalid: unable to decode OptString to nil")
	}
	// Check if the value is null and handle it gracefully
	if d.Next() == jx.Null {
		if err := d.Null(); err != nil {
			return err
		}
		// For null values, treat as unset (not present)
		o.Set = false
		o.Value = ""
		return nil
	}
	// Value is present and not null
	o.Set = true
	v, err := d.Str()`
)

func main() {
	fmt.Printf("Patching %s for OptString null handling...\n", targetFile)

	// Read the file
	content, err := os.ReadFile(targetFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Create backup
	backupFile := targetFile + ".backup"
	if err := os.WriteFile(backupFile, content, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating backup: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Backup created: %s\n", backupFile)

	// Apply the fix
	re := regexp.MustCompile(oldPattern)
	if !re.Match(content) {
		fmt.Println("Pattern not found - either already patched or ogen version changed")
		fmt.Println("Please verify the generated code manually")
		os.Exit(0)
	}

	newContent := re.ReplaceAll(content, []byte(newCode))

	// Verify the replacement worked
	if bytes.Equal(content, newContent) {
		fmt.Println("No changes made - pattern may have already been fixed")
		os.Exit(0)
	}

	// Write the patched file
	if err := os.WriteFile(targetFile, newContent, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing patched file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Successfully patched OptString.Decode() for null handling")
	fmt.Println("Note: This is a temporary fix until ogen addresses this upstream")
}

