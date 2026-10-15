// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package blob

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type UnrecognizedSchemeError struct {
	Scheme string
}

// InputTooLargeError reports that externally supplied verification material
// exceeded the caller's limit. Limiting reads is particularly important for
// URL inputs, where the remote server may omit or misstate Content-Length.
type InputTooLargeError struct {
	Reference string
	Limit     int64
}

func (e *InputTooLargeError) Error() string {
	return fmt.Sprintf("loading %s: input exceeds %d bytes", e.Reference, e.Limit)
}

func (e *UnrecognizedSchemeError) Error() string {
	return fmt.Sprintf("loading URL: unrecognized scheme: %s", e.Scheme)
}

func LoadFileOrURL(fileRef string) ([]byte, error) {
	return loadFileOrURL(fileRef, 0)
}

// LoadFileOrURLWithLimit loads a file, URL, or environment variable while
// refusing inputs larger than maxBytes. A non-positive limit is rejected so a
// security-sensitive caller cannot accidentally disable the bound.
func LoadFileOrURLWithLimit(fileRef string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("loading %s: maximum size must be positive", fileRef)
	}
	return loadFileOrURL(fileRef, maxBytes)
}

func loadFileOrURL(fileRef string, maxBytes int64) ([]byte, error) {
	var raw []byte
	var err error
	parts := strings.SplitAfterN(fileRef, "://", 2)
	if len(parts) == 2 {
		scheme := parts[0]
		switch scheme {
		case "http://":
			fallthrough
		case "https://":
			// #nosec G107
			resp, err := http.Get(fileRef)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return nil, fmt.Errorf("loading URL %s: server returned HTTP %d", fileRef, resp.StatusCode)
			}
			if maxBytes > 0 && resp.ContentLength > maxBytes {
				return nil, &InputTooLargeError{Reference: fileRef, Limit: maxBytes}
			}
			raw, err = readAll(resp.Body, fileRef, maxBytes)
			if err != nil {
				return nil, err
			}
		case "env://":
			envVar := parts[1]
			// Most of Cosign should use `env.LookupEnv` (see #2236) to restrict us to known environment variables
			// (usually `$COSIGN_*`). However, in this case, `envVar` is user-provided and not one of the allow-listed
			// env vars.
			value, found := os.LookupEnv(envVar) //nolint:forbidigo
			if !found {
				return nil, fmt.Errorf("loading URL: env var $%s not found", envVar)
			}
			raw = []byte(value)
			if maxBytes > 0 && int64(len(raw)) > maxBytes {
				return nil, &InputTooLargeError{Reference: fileRef, Limit: maxBytes}
			}
		default:
			return nil, &UnrecognizedSchemeError{Scheme: scheme}
		}
	} else {
		path := filepath.Clean(fileRef)
		if maxBytes > 0 {
			file, openErr := os.Open(path)
			if openErr != nil {
				return nil, openErr
			}
			defer file.Close()
			raw, err = readAll(file, fileRef, maxBytes)
		} else {
			raw, err = os.ReadFile(path)
		}
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func readAll(reader io.Reader, reference string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return io.ReadAll(reader)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, &InputTooLargeError{Reference: reference, Limit: maxBytes}
	}
	return raw, nil
}

func LoadFileOrURLWithChecksum(fileRef string, checksum string) ([]byte, error) {
	checksumParts := strings.Split(checksum, ":")
	if len(checksumParts) >= 3 {
		return nil, fmt.Errorf("wrong checksum input format, must have at most 1 colon: %s", checksum)
	}

	checksumAlgo := sha256.New()
	checksumValue := checksumParts[len(checksumParts)-1]
	if len(checksumParts) == 2 {
		switch checksumParts[0] {
		case "sha256": // the default set above
		case "sha512":
			checksumAlgo = sha512.New()
		default:
			return nil, fmt.Errorf("unsupported checksum algorithm: %s", checksumParts[0])
		}
	}

	fileContent, err := LoadFileOrURL(fileRef)
	if err != nil {
		return nil, err
	}

	checksumAlgo.Write(fileContent)
	computedChecksum := checksumAlgo.Sum(nil)
	// Compare the digests rather than their hex spellings: hex is case-insensitive
	// and checksums are frequently published in upper case, which a plain string
	// comparison would reject. A value that is not valid hex cannot match either.
	expectedChecksum, err := hex.DecodeString(checksumValue)
	if err != nil || !bytes.Equal(computedChecksum, expectedChecksum) {
		return nil, fmt.Errorf("incorrect checksum for file %s: expected %s but got %s", fileRef, checksumValue, hex.EncodeToString(computedChecksum))
	}

	return fileContent, nil
}
