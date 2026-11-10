// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srp

import (
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
)

// canonicalSignerName expands length-delimited labels without a dotted-string
// roundtrip. Literal dots and non-ASCII octets are label data; DNS canonical
// case folding applies only to ASCII A-Z. Pointer rules match dns.ReadName.
func canonicalSignerName(data []byte, offset int) ([]byte, error) {
	result := make([]byte, 0, dns.MaxNameSize)
	minimum := offset
	for {
		label, next, pointer, err := dns.ReadLabel(data, offset)
		if pointer {
			if next >= minimum {
				return nil, errors.ErrParse
			}
			minimum, offset = next, next
			continue
		}
		if err == errors.ErrNotFound {
			return append(result, 0), nil
		}
		if err != nil {
			return nil, err
		}
		if len(result)+1+len(label)+1 > dns.MaxNameSize {
			return nil, errors.ErrParse
		}
		result = append(result, byte(len(label)))
		for i := range len(label) {
			octet := label[i]
			if octet >= 'A' && octet <= 'Z' {
				octet += 'a' - 'A'
			}
			result = append(result, octet)
		}
		offset = next
	}
}
