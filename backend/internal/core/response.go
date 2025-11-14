package core

import (
	"encoding/xml"
	"net/http"
)

func WriteXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)

	if err := xml.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "Failed to encode XML", http.StatusInternalServerError)
	}
}
