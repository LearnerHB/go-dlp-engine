package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode error: %v", err)
	}
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Text == "" {
		http.Error(w, "Missing text field", http.StatusBadRequest)
		return
	}
	if len(req.Text) > 10000 {
		http.Error(w, "Text too long (max 10000 chars)", http.StatusBadRequest)
		return
	}

	locale := req.Locale
	if locale == "" {
		locale = "zh"
	}

	result := scanText(req.Text, locale)
	writeJSON(w, http.StatusOK, result)
}

func handleDesensitize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Text == "" {
		http.Error(w, "Missing text field", http.StatusBadRequest)
		return
	}
	if len(req.Text) > 10000 {
		http.Error(w, "Text too long (max 10000 chars)", http.StatusBadRequest)
		return
	}

	locale := req.Locale
	if locale == "" {
		locale = "zh"
	}

	result := desensitizeText(req.Text, locale)
	writeJSON(w, http.StatusOK, result)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	port := os.Getenv("DLP_ENGINE_PORT")
	if port == "" {
		port = "8082"
	}

	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/desensitize", handleDesensitize)
	http.HandleFunc("/health", handleHealth)

	log.Printf("Go DLP Engine listening on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
