package httpapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"quantumgate/internal/gateway"
)

type decisionRequest struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	IdentityToken string `json:"identity_token"`
}

type decisionResponse struct {
	RequestID              string     `json:"request_id"`
	TenantID               string     `json:"tenant_id"`
	ApplicationID          string     `json:"application_id"`
	Method                 string     `json:"method"`
	Path                   string     `json:"path"`
	ProfileID              string     `json:"profile_id"`
	ProfileRegistryVersion int64      `json:"profile_registry_version"`
	ProfileHash            string     `json:"profile_hash"`
	PolicyRevisionID       string     `json:"policy_revision_id"`
	Mode                   string     `json:"mode"`
	Decision               string     `json:"decision"`
	ReasonCodes            []string   `json:"reason_codes"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
}

func (s *Server) evaluateDecision(w http.ResponseWriter, r *http.Request) {
	applicationID := r.PathValue("application_id")
	authenticatedApplicationID, _ := r.Context().Value(serviceApplicationContextKey{}).(string)
	if !validUUID(applicationID) || applicationID != authenticatedApplicationID {
		s.notFound(w, r)
		return
	}
	route := gateway.Route{TenantID: contextTenant(r), ApplicationID: applicationID}
	request := gateway.Request{
		RequestID: requestID(r.Context()),
		ClientIP:  clientIPDimension(r.RemoteAddr),
	}
	if profileID, ok := gateway.TLSProfile(r.TLS); ok {
		request.ProfileID = profileID
	}
	var input decisionRequest
	if err := decodeControlJSON(w, r, &input); err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		s.rejectDecisionRequest(w, r, route, request, "INVALID_DECISION_REQUEST", status)
		return
	}
	if !validDecisionRequest(input) {
		s.rejectDecisionRequest(w, r, route, request, "INVALID_DECISION_REQUEST", http.StatusBadRequest)
		return
	}
	request.Method = input.Method
	request.Path = input.Path
	request.IdentityToken = input.IdentityToken
	if request.ProfileID == "" {
		s.rejectDecisionRequest(w, r, route, request, "DECISION_TRANSPORT_REJECTED", http.StatusForbidden)
		return
	}

	decision, err := s.EvaluateSDK(r.Context(), route, request)
	if err != nil {
		writeDecisionFailure(w, r, err)
		return
	}
	profileHash := profileDefinitionHash(request.ProfileID)
	response := decisionResponse{
		RequestID: request.RequestID, TenantID: route.TenantID, ApplicationID: route.ApplicationID,
		Method: request.Method, Path: request.Path, ProfileID: request.ProfileID,
		ProfileRegistryVersion: policyRegistryVersion, ProfileHash: hex.EncodeToString(profileHash[:]),
		PolicyRevisionID: decision.PolicyRevisionID, Mode: decision.Mode, Decision: decision.Outcome,
		ReasonCodes: decision.ReasonCodes, ExpiresAt: decision.ExpiresAt,
	}
	w.Header().Set("X-QG-Transport-Profile", request.ProfileID)
	w.Header().Set("X-QG-Policy-Revision", decision.PolicyRevisionID)
	writeJSON(w, http.StatusOK, response)
}

func validDecisionRequest(input decisionRequest) bool {
	return validPolicyMethod(input.Method) && validPolicyPath(input.Path) && validBoundedToken(input.IdentityToken, 16<<10)
}

func (s *Server) rejectDecisionRequest(w http.ResponseWriter, r *http.Request, route gateway.Route, request gateway.Request, code string, status int) {
	decision := gateway.Decision{Outcome: "deny", ReasonCodes: []string{code}}
	if err := s.recordDecisionEvent(r.Context(), contextTransaction(r), route, request, "sdk",
		"application:"+route.ApplicationID, decision, "failure", code); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE", "Service unavailable", "The request could not be processed safely.", true)
		return
	}
	writeProblem(w, r, status, code, "Request rejected", "The decision request could not be processed safely.", false)
}

func writeDecisionFailure(w http.ResponseWriter, r *http.Request, err error) {
	var failure *gateway.Failure
	if !errors.As(err, &failure) {
		writeProblem(w, r, http.StatusServiceUnavailable, "DATA_PLANE_UNAVAILABLE", "Service unavailable", "The request could not be evaluated safely.", true)
		return
	}
	if failure.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(failure.RetryAfter))
	}
	retryable := failure.StatusCode >= http.StatusInternalServerError || failure.StatusCode == http.StatusTooManyRequests
	writeProblem(w, r, failure.StatusCode, failure.Code, "Decision unavailable", "The request could not be evaluated safely.", retryable)
}
