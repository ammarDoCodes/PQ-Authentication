package httpapi

import "testing"

func TestProfileDesignRecordRequiresReviewEvidence(t *testing.T) {
	classical := profileDesignRecord{
		StandardProfile:        "TLS 1.3 RFC 8446",
		ClassicalMechanisms:    []string{"X25519"},
		KeyPurposeAndLifecycle: "Transport key exchange; negotiated per TLS 1.3 connection.",
		DowngradeDetection:     "Negotiation requires TLS 1.3 and a registered group.",
		TranscriptBinding:      "The maintained TLS implementation binds handshake messages.",
		TestVectors:            []string{"https://vectors.example/tls13"},
		InteropPartners:        []string{"Example TLS implementation"},
		DeprecationPlan:        "Disable the profile when the registry version is superseded.",
		RollbackPlan:           "Return the tenant to observe-only mode.",
	}
	if !validProfileDesignRecord("classical-approved", classical) {
		t.Fatal("complete classical profile record rejected")
	}

	hybrid := classical
	hybrid.StandardProfile = "TLS 1.3 X25519+ML-KEM-768 provider profile"
	hybrid.ClassicalMechanisms = []string{"X25519"}
	hybrid.PQCMechanisms = []string{"ML-KEM-768"}
	if !validProfileDesignRecord("hybrid-approved", hybrid) {
		t.Fatal("complete hybrid profile record rejected")
	}

	cases := []struct {
		name   string
		mode   string
		record profileDesignRecord
	}{
		{name: "missing standard", mode: "classical-approved", record: func() profileDesignRecord { r := classical; r.StandardProfile = ""; return r }()},
		{name: "missing mechanism", mode: "classical-approved", record: func() profileDesignRecord { r := classical; r.ClassicalMechanisms = nil; return r }()},
		{name: "duplicate mechanism", mode: "classical-approved", record: func() profileDesignRecord {
			r := classical
			r.ClassicalMechanisms = []string{"X25519", "X25519"}
			return r
		}()},
		{name: "missing vectors", mode: "classical-approved", record: func() profileDesignRecord { r := classical; r.TestVectors = nil; return r }()},
		{name: "unsafe vector URI", mode: "classical-approved", record: func() profileDesignRecord {
			r := classical
			r.TestVectors = []string{"http://vectors.example/test"}
			return r
		}()},
		{name: "missing interop partner", mode: "classical-approved", record: func() profileDesignRecord { r := classical; r.InteropPartners = nil; return r }()},
		{name: "missing downgrade behavior", mode: "classical-approved", record: func() profileDesignRecord { r := classical; r.DowngradeDetection = ""; return r }()},
		{name: "hybrid missing PQC mechanism", mode: "hybrid-approved", record: classical},
		{name: "oversized vector list", mode: "classical-approved", record: func() profileDesignRecord { r := classical; r.TestVectors = make([]string, 17); return r }()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if validProfileDesignRecord(test.mode, test.record) {
				t.Fatal("incomplete or unsafe profile evidence was accepted")
			}
		})
	}
}

func TestProfileReviewETagAndHTTPSReferenceValidation(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	one := profileReviewETag(id, 1)
	two := profileReviewETag(id, 2)
	if one == two || one != `"10000000-0000-4000-8000-000000000001-v1"` {
		t.Fatalf("profile ETag must bind the resource and lifecycle version: %q %q", one, two)
	}
	for _, reference := range []string{"", "http://example.test/review", "https://user:pass@example.test/review", "https://example.test/with space", "https://example.test/review\n"} {
		if validHTTPSReference(reference) {
			t.Errorf("unsafe or malformed review reference accepted: %q", reference)
		}
	}
	if !validHTTPSReference("https://security.example/reviews/profile-17") {
		t.Fatal("valid HTTPS review reference rejected")
	}
}

func TestProfileDefinitionHashBindsRegistryMetadata(t *testing.T) {
	const profileID = "tls13-classical"
	first := profileDefinitionHash(profileID)
	if second := profileDefinitionHash(profileID); first != second {
		t.Fatal("same profile definition produced different hashes")
	}
	original := policyProfiles[profileID]
	changed := original
	changed.ProviderVersion = original.ProviderVersion + "-changed"
	policyProfiles[profileID] = changed
	second := profileDefinitionHash(profileID)
	policyProfiles[profileID] = original
	if first == second {
		t.Fatal("profile hash did not change when registry metadata changed")
	}
}
