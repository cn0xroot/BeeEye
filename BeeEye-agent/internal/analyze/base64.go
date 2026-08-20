package analyze

import "encoding/base64"

// base64Decode accepts both standard and URL-safe alphabets, with or without
// padding. Captures come from other people's software, and being strict about
// which variant a credential was encoded with would only lose findings.
func base64Decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, base64.CorruptInputError(0)
}
