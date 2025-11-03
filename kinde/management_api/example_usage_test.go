package management_api

import (
	"fmt"

	"github.com/go-faster/jx"
)

// ExamplePermissions_Decode_nullDescription demonstrates handling of null values
func ExamplePermissions_Decode_nullDescription() {
	// JSON with null description (common from Kinde API)
	jsonData := `{
		"id": "019a12ad-0dad-117d-a831-083bf2fdab86",
		"key": "cmi:show:dashboard",
		"name": "CMI Show Dashboard",
		"description": null
	}`

	d := jx.DecodeBytes([]byte(jsonData))
	var perm Permissions

	err := perm.Decode(d)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Access the decoded values
	if id, ok := perm.ID.Get(); ok {
		fmt.Printf("ID: %s\n", id)
	}

	if key, ok := perm.Key.Get(); ok {
		fmt.Printf("Key: %s\n", key)
	}

	if name, ok := perm.Name.Get(); ok {
		fmt.Printf("Name: %s\n", name)
	}

	// Description is null, so IsSet() returns false
	if perm.Description.IsSet() {
		desc, _ := perm.Description.Get()
		fmt.Printf("Description: %s\n", desc)
	} else {
		fmt.Println("Description: not set")
	}

	// Output:
	// ID: 019a12ad-0dad-117d-a831-083bf2fdab86
	// Key: cmi:show:dashboard
	// Name: CMI Show Dashboard
	// Description: not set
}

// ExamplePermissions_Decode_withDescription demonstrates handling of string values
func ExamplePermissions_Decode_withDescription() {
	// JSON with valid description
	jsonData := `{
		"id": "019a12ad-0dad-117d-a831-083bf2fdab86",
		"key": "cmi:show:dashboard",
		"name": "CMI Show Dashboard",
		"description": "Allows showing the CMI dashboard"
	}`

	d := jx.DecodeBytes([]byte(jsonData))
	var perm Permissions

	err := perm.Decode(d)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Access the decoded values
	if name, ok := perm.Name.Get(); ok {
		fmt.Printf("Name: %s\n", name)
	}

	if desc, ok := perm.Description.Get(); ok {
		fmt.Printf("Description: %s\n", desc)
	}

	// Output:
	// Name: CMI Show Dashboard
	// Description: Allows showing the CMI dashboard
}

// ExampleGetPermissionsResponse_Decode demonstrates the real-world API scenario
func ExampleGetPermissionsResponse_Decode() {
	// Real API response with null description
	apiResponse := `{
		"code": "OK",
		"message": "Success",
		"next_token": "MTo6OmlkX2Rlc2M=",
		"permissions": [
			{
				"id": "1",
				"key": "read:users",
				"name": "Read Users",
				"description": "Can read user data"
			},
			{
				"id": "2",
				"key": "write:users",
				"name": "Write Users",
				"description": null
			}
		]
	}`

	d := jx.DecodeBytes([]byte(apiResponse))
	var response GetPermissionsResponse

	err := response.Decode(d)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Decoded %d permissions successfully\n", len(response.Permissions))

	for i, perm := range response.Permissions {
		if name, ok := perm.Name.Get(); ok {
			fmt.Printf("Permission %d: %s", i+1, name)
			if desc, ok := perm.Description.Get(); ok {
				fmt.Printf(" - %s\n", desc)
			} else {
				fmt.Println(" - no description")
			}
		}
	}

	// Output:
	// Decoded 2 permissions successfully
	// Permission 1: Read Users - Can read user data
	// Permission 2: Write Users - no description
}

