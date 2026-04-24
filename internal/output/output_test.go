package output_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/output"
	"github.com/aurlaw/secretscanner/internal/scanner"
)

var testFindings = []findings.Finding{
	{
		File:     "cmd/config.go",
		Line:     14,
		Pattern:  "test-key",
		Severity: findings.Critical,
		Preview:  `export KEY="TESTKEY-[REDACTED]"`,
	},
	{
		File:     "cmd/config.go",
		Line:     22,
		Pattern:  "test-key",
		Severity: findings.High,
		Preview:  `var other = "TESTKEY-[REDACTED]"`,
	},
	{
		File:     "internal/db.go",
		Line:     5,
		Pattern:  "test-key",
		Severity: findings.Critical,
		Preview:  `db = "TESTKEY-[REDACTED]"`,
	},
}

var testSummary = scanner.ScanSummary{
	FilesScanned: 42,
	FilesSkipped: 3,
	Elapsed:      1203 * time.Millisecond,
}

// WriteText tests

func TestWriteText_Header(t *testing.T) {
	var buf strings.Builder
	output.WriteText(&buf, testFindings, testSummary)
	got := buf.String()

	if !strings.Contains(got, "findings in 2 files") {
		t.Errorf("expected header %q in output:\n%s", "findings in 2 files", got)
	}
}

func TestWriteText_FindingLines(t *testing.T) {
	var buf strings.Builder
	output.WriteText(&buf, testFindings, testSummary)
	got := buf.String()

	if !strings.Contains(got, "cmd/config.go:14") {
		t.Errorf("expected finding line with file:line in output:\n%s", got)
	}
	if !strings.Contains(got, "[critical]") {
		t.Errorf("expected [critical] in output:\n%s", got)
	}
	if !strings.Contains(got, "test-key") {
		t.Errorf("expected pattern name in output:\n%s", got)
	}
}

func TestWriteText_FindingPreview(t *testing.T) {
	var buf strings.Builder
	output.WriteText(&buf, testFindings, testSummary)
	got := buf.String()

	if !strings.Contains(got, "  export KEY=") {
		t.Errorf("expected indented preview in output:\n%s", got)
	}
}

func TestWriteText_SummaryCounts(t *testing.T) {
	var buf strings.Builder
	output.WriteText(&buf, testFindings, testSummary)
	got := buf.String()

	if !strings.Contains(got, "42") {
		t.Errorf("expected files scanned count in output:\n%s", got)
	}
	if !strings.Contains(got, "3") {
		t.Errorf("expected files skipped count in output:\n%s", got)
	}
}

func TestWriteText_Elapsed(t *testing.T) {
	var buf strings.Builder
	output.WriteText(&buf, testFindings, testSummary)
	got := buf.String()

	if !strings.Contains(got, "1.203s") {
		t.Errorf("expected elapsed '1.203s' in output:\n%s", got)
	}
}

func TestWriteText_SeverityCountsOnlyPresent(t *testing.T) {
	var buf strings.Builder
	output.WriteText(&buf, testFindings, testSummary)
	got := buf.String()

	if !strings.Contains(got, "critical:") {
		t.Errorf("expected critical severity line in output:\n%s", got)
	}
	if !strings.Contains(got, "high:") {
		t.Errorf("expected high severity line in output:\n%s", got)
	}
	if strings.Contains(got, "medium:") {
		t.Errorf("output should not contain medium severity line when count is 0:\n%s", got)
	}
	if strings.Contains(got, "low:") {
		t.Errorf("output should not contain low severity line when count is 0:\n%s", got)
	}
}

func TestWriteText_NoFindings(t *testing.T) {
	var buf strings.Builder
	output.WriteText(&buf, []findings.Finding{}, testSummary)
	got := buf.String()

	if !strings.Contains(got, "no findings") {
		t.Errorf("expected 'no findings' in output:\n%s", got)
	}
}

// WriteJSON tests

func TestWriteJSON_ValidJSON(t *testing.T) {
	var buf strings.Builder
	if err := output.WriteJSON(&buf, testFindings, testSummary); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}
}

func TestWriteJSON_FindingsCount(t *testing.T) {
	var buf strings.Builder
	output.WriteJSON(&buf, testFindings, testSummary)

	var result map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &result)

	arr, ok := result["findings"].([]interface{})
	if !ok {
		t.Fatalf("findings is not an array")
	}
	if len(arr) != 3 {
		t.Errorf("findings count = %d, want 3", len(arr))
	}
}

func TestWriteJSON_FindingFields(t *testing.T) {
	var buf strings.Builder
	output.WriteJSON(&buf, testFindings, testSummary)

	var result map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &result)

	arr := result["findings"].([]interface{})
	first := arr[0].(map[string]interface{})

	if first["file"] != "cmd/config.go" {
		t.Errorf("file = %v, want cmd/config.go", first["file"])
	}
	if first["line"].(float64) != 14 {
		t.Errorf("line = %v, want 14", first["line"])
	}
	if first["pattern"] != "test-key" {
		t.Errorf("pattern = %v, want test-key", first["pattern"])
	}
}

func TestWriteJSON_SeverityIsString(t *testing.T) {
	var buf strings.Builder
	output.WriteJSON(&buf, testFindings, testSummary)

	var result map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &result)

	arr := result["findings"].([]interface{})
	first := arr[0].(map[string]interface{})

	sev, ok := first["severity"].(string)
	if !ok {
		t.Fatalf("severity is not a string, got %T", first["severity"])
	}
	if sev != "critical" {
		t.Errorf("severity = %q, want critical", sev)
	}
}

func TestWriteJSON_SummaryFields(t *testing.T) {
	var buf strings.Builder
	output.WriteJSON(&buf, testFindings, testSummary)

	var result map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &result)

	sum := result["summary"].(map[string]interface{})

	if sum["filesScanned"].(float64) != 42 {
		t.Errorf("filesScanned = %v, want 42", sum["filesScanned"])
	}
	if sum["filesSkipped"].(float64) != 3 {
		t.Errorf("filesSkipped = %v, want 3", sum["filesSkipped"])
	}
	if sum["totalFindings"].(float64) != 3 {
		t.Errorf("totalFindings = %v, want 3", sum["totalFindings"])
	}
	if sum["elapsedMs"].(float64) != 1203 {
		t.Errorf("elapsedMs = %v, want 1203", sum["elapsedMs"])
	}
}

func TestWriteJSON_EmptyFindingsNotNull(t *testing.T) {
	var buf strings.Builder
	output.WriteJSON(&buf, []findings.Finding{}, testSummary)

	var result map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &result)

	findingsVal, ok := result["findings"]
	if !ok {
		t.Fatal("findings key missing")
	}
	if _, isSlice := findingsVal.([]interface{}); !isSlice {
		t.Errorf("findings should be a JSON array, got %T", findingsVal)
	}
}

func TestWriteJSON_AllSeverityCountsPresent(t *testing.T) {
	var buf strings.Builder
	output.WriteJSON(&buf, testFindings, testSummary)

	var result map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &result)

	summaryMap := result["summary"].(map[string]interface{})
	for _, key := range []string{"critical", "high", "medium", "low"} {
		if _, ok := summaryMap[key]; !ok {
			t.Errorf("summary missing key %q", key)
		}
	}
}
