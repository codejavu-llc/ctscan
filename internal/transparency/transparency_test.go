package transparency

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCrtSHSearchNormalizesAndScopesNames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("q") != "%.example.com" {
			t.Errorf("unexpected query %q", request.URL.RawQuery)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`[{"id":42,"name_value":"*.API.Example.com\nother.test","issuer_name":"Test CA","not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00"}]`))
	}))
	defer server.Close()
	provider, err := New("crtsh", ClientConfig{HTTPClient: server.Client(), BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	records, err := provider.Search(context.Background(), "example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(records[0].DNSNames) != 1 || records[0].DNSNames[0] != "api.example.com" {
		t.Fatalf("unexpected records %#v", records)
	}
}

func TestCertSpotterRequiresToken(t *testing.T) {
	if _, err := New("certspotter", ClientConfig{}); err == nil {
		t.Fatal("expected missing token error")
	}
}
