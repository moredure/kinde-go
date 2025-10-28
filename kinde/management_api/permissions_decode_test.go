package management_api

import (
	"testing"

	"github.com/go-faster/jx"
)

func TestPermissions_Decode_WithNullDescription(t *testing.T) {
	tests := []struct {
		name               string
		json               string
		wantErr            bool
		wantDescriptionSet bool
		wantDescription    string
	}{
		{
			name: "permission with null description should succeed and be treated as unset",
			json: `{
				"id": "019a12ad-0dad-117d-a831-083bf2fdab86",
				"key": "cmi:show:dashboard",
				"name": "CMI Show Dashboard",
				"description": null
			}`,
			wantErr:            false,
			wantDescriptionSet: false, // null is treated as unset
		},
		{
			name: "permission with string description should succeed",
			json: `{
				"id": "019a12ad-0dad-117d-a831-083bf2fdab86",
				"key": "cmi:show:dashboard",
				"name": "CMI Show Dashboard",
				"description": "This is a description"
			}`,
			wantErr:            false,
			wantDescriptionSet: true,
			wantDescription:    "This is a description",
		},
		{
			name: "permission without description field should succeed",
			json: `{
				"id": "019a12ad-0dad-117d-a831-083bf2fdab86",
				"key": "cmi:show:dashboard",
				"name": "CMI Show Dashboard"
			}`,
			wantErr:            false,
			wantDescriptionSet: false,
		},
		{
			name: "permission with empty string description should succeed",
			json: `{
				"id": "019a12ad-0dad-117d-a831-083bf2fdab86",
				"key": "cmi:show:dashboard",
				"name": "CMI Show Dashboard",
				"description": ""
			}`,
			wantErr:            false,
			wantDescriptionSet: true,
			wantDescription:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := jx.DecodeBytes([]byte(tt.json))
			var p Permissions

			err := p.Decode(d)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Permissions.Decode() expected error but got nil")
					return
				}
				t.Logf("Expected error occurred: %v", err)
			} else {
				if err != nil {
					t.Errorf("Permissions.Decode() unexpected error = %v", err)
					return
				}

				// Verify the decoded values
				if id, ok := p.ID.Get(); ok {
					if id != "019a12ad-0dad-117d-a831-083bf2fdab86" {
						t.Errorf("ID = %v, want %v", id, "019a12ad-0dad-117d-a831-083bf2fdab86")
					}
				}

				if key, ok := p.Key.Get(); ok {
					if key != "cmi:show:dashboard" {
						t.Errorf("Key = %v, want %v", key, "cmi:show:dashboard")
					}
				}

				if name, ok := p.Name.Get(); ok {
					if name != "CMI Show Dashboard" {
						t.Errorf("Name = %v, want %v", name, "CMI Show Dashboard")
					}
				}

				// Verify description handling
				if p.Description.IsSet() != tt.wantDescriptionSet {
					t.Errorf("Description.IsSet() = %v, want %v", p.Description.IsSet(), tt.wantDescriptionSet)
				}

				if tt.wantDescriptionSet {
					if desc, ok := p.Description.Get(); ok {
						if desc != tt.wantDescription {
							t.Errorf("Description = %v, want %v", desc, tt.wantDescription)
						}
					} else {
						t.Errorf("Description should be set but Get() returned not ok")
					}
				}
			}
		})
	}
}

func TestGetPermissionsResponse_Decode_WithNullDescription(t *testing.T) {
	// This test simulates the real-world scenario from the issue
	// After the fix, this should succeed instead of failing
	json := `{
		"code": "OK",
		"message": "Success",
		"next_token": "MTo6OmlkX2Rlc2M=",
		"permissions": [
			{
				"id": "019a12ad-0dad-117d-a831-083bf2fdab86",
				"key": "cmi:show:dashboard",
				"name": "CMI Show Dashboard",
				"description": null
			}
		]
	}`

	d := jx.DecodeBytes([]byte(json))
	var response GetPermissionsResponse

	err := response.Decode(d)

	if err != nil {
		t.Fatalf("GetPermissionsResponse.Decode() unexpected error = %v", err)
	}

	// Verify the response was decoded correctly
	if len(response.Permissions) != 1 {
		t.Errorf("Expected 1 permission, got %d", len(response.Permissions))
		return
	}

	perm := response.Permissions[0]

	// Verify permission fields
	if id, ok := perm.ID.Get(); ok {
		if id != "019a12ad-0dad-117d-a831-083bf2fdab86" {
			t.Errorf("ID = %v, want %v", id, "019a12ad-0dad-117d-a831-083bf2fdab86")
		}
	} else {
		t.Error("ID should be set")
	}

	if key, ok := perm.Key.Get(); ok {
		if key != "cmi:show:dashboard" {
			t.Errorf("Key = %v, want %v", key, "cmi:show:dashboard")
		}
	} else {
		t.Error("Key should be set")
	}

	if name, ok := perm.Name.Get(); ok {
		if name != "CMI Show Dashboard" {
			t.Errorf("Name = %v, want %v", name, "CMI Show Dashboard")
		}
	} else {
		t.Error("Name should be set")
	}

	// Description should be unset (treated as not present) since it was null
	if perm.Description.IsSet() {
		t.Error("Description should not be set when null")
	}

	t.Log("Successfully decoded GetPermissionsResponse with null description")
}

func TestOptString_Decode_WithNull(t *testing.T) {
	tests := []struct {
		name       string
		json       string
		wantErr    bool
		wantSet    bool
		wantValue  string
	}{
		{
			name:       "null value should be handled gracefully as unset",
			json:       `null`,
			wantErr:    false,
			wantSet:    false,
			wantValue:  "",
		},
		{
			name:       "string value should succeed",
			json:       `"test string"`,
			wantErr:    false,
			wantSet:    true,
			wantValue:  "test string",
		},
		{
			name:       "empty string should succeed",
			json:       `""`,
			wantErr:    false,
			wantSet:    true,
			wantValue:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := jx.DecodeBytes([]byte(tt.json))
			var opt OptString

			err := opt.Decode(d)

			if tt.wantErr {
				if err == nil {
					t.Errorf("OptString.Decode() expected error but got nil")
					return
				}
				t.Logf("Expected error occurred: %v", err)
			} else {
				if err != nil {
					t.Errorf("OptString.Decode() unexpected error = %v", err)
					return
				}

				// Verify IsSet() matches expectation
				if opt.IsSet() != tt.wantSet {
					t.Errorf("IsSet() = %v, want %v", opt.IsSet(), tt.wantSet)
				}

				// Verify value if it should be set
				if tt.wantSet {
					if val, ok := opt.Get(); ok {
						if val != tt.wantValue {
							t.Errorf("Get() = %v, want %v", val, tt.wantValue)
						}
					} else {
						t.Error("Get() returned not ok, but IsSet() was true")
					}
				}
			}
		})
	}
}

func TestOptNilString_Decode_WithNull(t *testing.T) {
	// This test shows that OptNilString handles null correctly
	tests := []struct {
		name     string
		json     string
		wantErr  bool
		wantNull bool
		wantSet  bool
	}{
		{
			name:     "null value should be handled correctly",
			json:     `null`,
			wantErr:  false,
			wantNull: true,
			wantSet:  true,
		},
		{
			name:     "string value should be handled correctly",
			json:     `"test string"`,
			wantErr:  false,
			wantNull: false,
			wantSet:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := jx.DecodeBytes([]byte(tt.json))
			var opt OptNilString

			err := opt.Decode(d)

			if tt.wantErr {
				if err == nil {
					t.Errorf("OptNilString.Decode() expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("OptNilString.Decode() unexpected error = %v", err)
					return
				}

				if opt.IsNull() != tt.wantNull {
					t.Errorf("IsNull() = %v, want %v", opt.IsNull(), tt.wantNull)
				}

				if opt.IsSet() != tt.wantSet {
					t.Errorf("IsSet() = %v, want %v", opt.IsSet(), tt.wantSet)
				}
			}
		})
	}
}

func TestGetPermissionsResponse_Decode_WithMixedDescriptions(t *testing.T) {
	// Test with multiple permissions having various description states
	json := `{
		"code": "OK",
		"message": "Success",
		"permissions": [
			{
				"id": "1",
				"key": "perm:one",
				"name": "Permission One",
				"description": "Valid description"
			},
			{
				"id": "2",
				"key": "perm:two",
				"name": "Permission Two",
				"description": null
			},
			{
				"id": "3",
				"key": "perm:three",
				"name": "Permission Three"
			},
			{
				"id": "4",
				"key": "perm:four",
				"name": "Permission Four",
				"description": ""
			}
		]
	}`

	d := jx.DecodeBytes([]byte(json))
	var response GetPermissionsResponse

	err := response.Decode(d)

	if err != nil {
		t.Fatalf("GetPermissionsResponse.Decode() unexpected error = %v", err)
	}

	if len(response.Permissions) != 4 {
		t.Fatalf("Expected 4 permissions, got %d", len(response.Permissions))
	}

	// Permission 1: Has description
	if desc, ok := response.Permissions[0].Description.Get(); !ok || desc != "Valid description" {
		t.Errorf("Permission 1: expected description 'Valid description', got ok=%v, value=%v", ok, desc)
	}

	// Permission 2: null description (should be unset)
	if response.Permissions[1].Description.IsSet() {
		t.Error("Permission 2: description should not be set when null")
	}

	// Permission 3: missing description (should be unset)
	if response.Permissions[2].Description.IsSet() {
		t.Error("Permission 3: description should not be set when missing")
	}

	// Permission 4: empty string description (should be set)
	if desc, ok := response.Permissions[3].Description.Get(); !ok || desc != "" {
		t.Errorf("Permission 4: expected empty description, got ok=%v, value=%v", ok, desc)
	}

	t.Log("Successfully decoded GetPermissionsResponse with mixed description states")
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

