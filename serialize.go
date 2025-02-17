// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/net/publicsuffix"
)

// MarshalJSON implements json.Marshaler by encoding all persistent cookies
// currently in the jar.
func (j *Jar) MarshalJSON() ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	data, _ := json.Marshal(j.entries)
	return data, nil
}

// UnmarshalJSON implements json.Unmarshaler by decoding all persistent cookies
// and storing them into the
func (j *Jar) UnmarshalJSON(r []byte) error {
	j.psList = publicsuffix.List

	buf := bytes.NewBuffer(r)
	decoder := json.NewDecoder(buf)
	// Cope with old cookiejar format by just discarding
	// cookies, but still return an error if it's invalid JSON.
	var data json.RawMessage
	if err := decoder.Decode(&data); err != nil {
		if err == io.EOF {
			// Empty file.
			return nil
		}
		return err
	}
	var entries map[string]map[string]entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("cookies in invalid format (error: %v)", err)
	}
	j.entries = entries
	return nil
}
