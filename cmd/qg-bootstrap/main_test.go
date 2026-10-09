package main

import "testing"

func TestBootstrapUUIDValidation(t *testing.T) {
	if !isUUID("10000000-0000-4000-8000-000000000001") {
		t.Fatal("valid UUID rejected")
	}
	for _, value := range []string{"", "10000000-0000-4000-8000-00000000000g", "not-a-uuid", " 10000000-0000-4000-8000-000000000001"} {
		if isUUID(value) {
			t.Errorf("invalid UUID accepted: %q", value)
		}
	}
}

func TestBootstrapIdentityAndLabelValidation(t *testing.T) {
	if !validIdentityPart("subject-123", 512) || !validLabel("Local environment", 80) {
		t.Fatal("expected ordinary bootstrap values to be valid")
	}
	for _, value := range []string{"", "line\nfeed", "tab\tvalue", "bad\x00value"} {
		if validIdentityPart(value, 512) {
			t.Errorf("identity control or empty value accepted: %q", value)
		}
	}
	if validLabel("padded ", 80) || validLabel("", 80) || validLabel("too long", 2) {
		t.Fatal("invalid bootstrap label accepted")
	}
}
