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
		return fmt.Errorf("failed to decode XML: %w", err)
	}

	return nil
}
