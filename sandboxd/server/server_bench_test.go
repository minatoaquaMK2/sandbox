package server

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"testing"
)

func BenchmarkWriteJSON(b *testing.B) {
	w := &jsonBenchWriter{header: http.Header{}}
	value := struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}{ID: "sb_bench", State: "running"}
	b.ReportAllocs()
	for b.Loop() {
		w.buffer.Reset()
		writeJSON(w, http.StatusOK, value)
	}
	var result map[string]string
	if err := json.Unmarshal(w.buffer.Bytes(), &result); err != nil || result["id"] != value.ID || result["state"] != value.State || w.status != http.StatusOK || w.header.Get("Content-Type") != "application/json" {
		b.Fatalf("response status=%d header=%v body=%s error=%v", w.status, w.header, w.buffer.Bytes(), err)
	}
}

type jsonBenchWriter struct {
	header http.Header
	buffer bytes.Buffer
	status int
}

func (w *jsonBenchWriter) Header() http.Header { return w.header }

func (w *jsonBenchWriter) Write(p []byte) (int, error) { return w.buffer.Write(p) }

func (w *jsonBenchWriter) WriteHeader(code int) { w.status = code }
