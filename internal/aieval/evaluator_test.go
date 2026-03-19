package aieval

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---- parseEvalResponse tests ----

func TestParseEvalResponse_JSONPass(t *testing.T) {
	status, reason := parseEvalResponse(`{"status": "PASS", "reason": "Code looks good"}`)
	if status != "PASS" {
		t.Errorf("status = %q, want PASS", status)
	}
	if reason != "Code looks good" {
		t.Errorf("reason = %q, want 'Code looks good'", reason)
	}
}

func TestParseEvalResponse_JSONFail(t *testing.T) {
	status, reason := parseEvalResponse(`{"status": "FAIL", "reason": "Missing error handling"}`)
	if status != "FAIL" {
		t.Errorf("status = %q, want FAIL", status)
	}
	if reason != "Missing error handling" {
		t.Errorf("reason = %q", reason)
	}
}

func TestParseEvalResponse_JSONWithCodeFence(t *testing.T) {
	input := "```json\n{\"status\": \"PASS\", \"reason\": \"All tests pass\"}\n```"
	status, _ := parseEvalResponse(input)
	if status != "PASS" {
		t.Errorf("status = %q, want PASS", status)
	}
}

func TestParseEvalResponse_FallbackTextPass(t *testing.T) {
	status, _ := parseEvalResponse("The code is production-ready. PASS.")
	if status != "PASS" {
		t.Errorf("status = %q, want PASS", status)
	}
}

func TestParseEvalResponse_FallbackTextFail(t *testing.T) {
	status, _ := parseEvalResponse("The code has critical bugs. FAIL.")
	if status != "FAIL" {
		t.Errorf("status = %q, want FAIL", status)
	}
}

func TestParseEvalResponse_Inconclusive(t *testing.T) {
	status, _ := parseEvalResponse("I'm not sure about this code.")
	if status != "INCONCLUSIVE" {
		t.Errorf("status = %q, want INCONCLUSIVE", status)
	}
}

func TestParseEvalResponse_CaseInsensitive(t *testing.T) {
	status, _ := parseEvalResponse(`{"status": "pass", "reason": "ok"}`)
	if status != "PASS" {
		t.Errorf("status = %q, want PASS", status)
	}
}

// ---- Mock API tests ----

func mockAnthropicServer(t *testing.T, status, reason string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("x-api-key") == "" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("anthropic-version") == "" {
			http.Error(w, "missing version", http.StatusBadRequest)
			return
		}

		// Parse request to verify structure
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)

		responseText := `{"status": "` + status + `", "reason": "` + reason + `"}`

		resp := map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": responseText},
			},
			"usage": map[string]any{
				"input_tokens":  150,
				"output_tokens": 30,
			},
			"stop_reason": "end_turn",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestEvaluate_EmptyPolicies(t *testing.T) {
	results, err := Evaluate(context.Background(), nil, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestEvaluate_NoAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	policies := []Policy{{Name: "test", Prompt: "check it"}}
	_, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err == nil {
		t.Fatal("Expected error for missing API key")
	}
}

func TestEvaluate_MockPass(t *testing.T) {
	server := mockAnthropicServer(t, "PASS", "Code is production-ready")
	defer server.Close()

	// Override the API URL for testing
	origURL := apiURL
	defer func() { setTestAPIURL(origURL) }()
	setTestAPIURL(server.URL)

	t.Setenv("ANTHROPIC_API_KEY", "test-key-123")

	policies := []Policy{
		{Name: "code-quality", Prompt: "PASS if code is production-ready. FAIL otherwise."},
	}
	materials := []byte(`{"actions": [{"tool": "Read", "file": "main.go"}]}`)

	results, err := Evaluate(context.Background(), policies, materials)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if !results[0].Passed {
		t.Errorf("Expected pass, got: %+v", results[0])
	}
	if results[0].Status != "PASS" {
		t.Errorf("Status = %q, want PASS", results[0].Status)
	}
	if results[0].TokensIn == 0 {
		t.Error("Expected non-zero token count")
	}
}

func TestEvaluate_MockFail(t *testing.T) {
	server := mockAnthropicServer(t, "FAIL", "Missing error handling in critical path")
	defer server.Close()

	origURL := apiURL
	defer func() { setTestAPIURL(origURL) }()
	setTestAPIURL(server.URL)

	t.Setenv("ANTHROPIC_API_KEY", "test-key-123")

	policies := []Policy{
		{Name: "error-handling", Prompt: "PASS if all errors are handled. FAIL otherwise."},
	}

	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Passed {
		t.Error("Expected fail")
	}
	if results[0].Status != "FAIL" {
		t.Errorf("Status = %q, want FAIL", results[0].Status)
	}
}

func TestEvaluate_MockAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error": {"message": "rate limited"}}`, http.StatusTooManyRequests)
	}))
	defer server.Close()

	origURL := apiURL
	defer func() { setTestAPIURL(origURL) }()
	setTestAPIURL(server.URL)

	t.Setenv("ANTHROPIC_API_KEY", "test-key-123")

	policies := []Policy{{Name: "test", Prompt: "check"}}
	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate should not return fatal error: %v", err)
	}
	// API errors become ERROR status, not fatal
	if results[0].Status != "ERROR" {
		t.Errorf("Status = %q, want ERROR", results[0].Status)
	}
}

func TestEvaluate_MultiplePolicies(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		status := "PASS"
		if callCount == 2 {
			status = "FAIL"
		}
		resp := map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf(`{"status": "%s", "reason": "test"}`, status)},
			},
			"usage":       map[string]any{"input_tokens": 100, "output_tokens": 20},
			"stop_reason": "end_turn",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	origURL := apiURL
	defer func() { setTestAPIURL(origURL) }()
	setTestAPIURL(server.URL)

	t.Setenv("ANTHROPIC_API_KEY", "test-key-123")

	policies := []Policy{
		{Name: "quality", Prompt: "check quality"},
		{Name: "security", Prompt: "check security"},
	}

	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}
	if !results[0].Passed {
		t.Error("First policy should pass")
	}
	if results[1].Passed {
		t.Error("Second policy should fail")
	}
}

// setTestAPIURL overrides the package-level API URL for testing.
func setTestAPIURL(url string) {
	apiURL = url
}
