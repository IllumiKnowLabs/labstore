package core

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

func ReadXML(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := xml.NewDecoder(r.Body)
	defer r.Body.Close()

	if err := decoder.Decode(&dst); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode XML: %s", err), http.StatusBadRequest)
		return fmt.Errorf("failed to decode XML: %w", err)
	}

	return nil
}
