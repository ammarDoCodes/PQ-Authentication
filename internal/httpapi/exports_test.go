package httpapi

import (
	"bytes"
	"strings"
	"testing"
)

func TestAuditExportEncryptionAuthenticatesContextAndCiphertext(t *testing.T) {
	server := &Server{RateLimitKey: bytes.Repeat([]byte("k"), 32)}
	plaintext := []byte(`{"tenant_id":"tenant-a","events":[]}`)
	tenantID := "10000000-0000-4000-8000-000000000001"
	exportID := "20000000-0000-4000-8000-000000000002"
	sealed, err := server.sealAuditExport(plaintext, tenantID, exportID)
	if err != nil {
		t.Fatal("seal export: ", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("encrypted export contains plaintext")
	}
	opened, err := server.openAuditExport(sealed, tenantID, exportID)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open export: got %q, err %v", opened, err)
	}
	if _, err := server.openAuditExport(sealed, "30000000-0000-4000-8000-000000000003", exportID); err == nil {
		t.Fatal("export decrypted under a different tenant")
	}
	if _, err := server.openAuditExport(sealed, tenantID, "40000000-0000-4000-8000-000000000004"); err == nil {
		t.Fatal("export decrypted under a different export ID")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := server.openAuditExport(sealed, tenantID, exportID); err == nil {
		t.Fatal("modified ciphertext was accepted")
	}
}

func TestGeneratedUUIDUsesRFC4122VersionFourShape(t *testing.T) {
	value, err := generateUUID()
	if err != nil {
		t.Fatal("generate UUID: ", err)
	}
	if !validUUID(value) || value[14] != '4' || !strings.ContainsRune("89ab", rune(value[19])) {
		t.Fatalf("generated identifier is not a version-four UUID: %q", value)
	}
}
