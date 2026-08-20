package mitm

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"text/template"
)

// MobileConfig returns an Apple Configuration Profile (.mobileconfig)
// wrapping this CA's certificate — installing this on iOS/iPadOS/macOS via
// Safari gives a named, described one-tap install prompt instead of a bare
// PEM file, which most people mistake for a document to open rather than a
// certificate to trust. It does NOT skip the platform's own second step:
// after installing the profile, Settings → General → About → Certificate
// Trust Settings still needs "Enable full trust for root certificates"
// switched on for this cert by hand — Apple requires that explicit step for
// any user-added root, profile or not, and no profile payload can bypass it.
func (ca *CA) MobileConfig() []byte {
	sum := sha256.Sum256(ca.cert.Raw)
	payloadUUID := uuidFromHash(sum[:], "payload")
	profileUUID := uuidFromHash(sum[:], "profile")
	b64 := base64.StdEncoding.EncodeToString(ca.cert.Raw)

	var buf bytes.Buffer
	// text/template, not fmt.Sprintf: the payload UUID/base64 are
	// machine-generated and cert-derived, never attacker input, but the
	// template still HTML/XML-escapes nothing on its own — %-encoding a
	// PEM/base64 blob has no special XML characters in it, so plain
	// substitution is safe here; a template just keeps the plist readable.
	mobileConfigTmpl.Execute(&buf, mobileConfigData{
		PayloadUUID: payloadUUID,
		ProfileUUID: profileUUID,
		CertB64:     wrap76(b64),
	})
	return buf.Bytes()
}

type mobileConfigData struct {
	PayloadUUID string
	ProfileUUID string
	CertB64     string
}

var mobileConfigTmpl = template.Must(template.New("mobileconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>beeeye-mitm-ca.pem</string>
			<key>PayloadContent</key>
			<data>
{{.CertB64}}
			</data>
			<key>PayloadDescription</key>
			<string>Adds the BeeEye local MITM root certificate, generated on your own gateway.</string>
			<key>PayloadDisplayName</key>
			<string>BeeEye Local MITM Root</string>
			<key>PayloadIdentifier</key>
			<string>io.beeeye.mitm.ca.{{.PayloadUUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{{.PayloadUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Lets this device opt into BeeEye's TLS decryption (F45) for its own traffic. After installing, go to Settings -&gt; General -&gt; About -&gt; Certificate Trust Settings and enable full trust for "BeeEye Local MITM Root" -&gt; that manual step is required by iOS for every user-added root and cannot be skipped by this profile.</string>
	<key>PayloadDisplayName</key>
	<string>BeeEye MITM Root Certificate</string>
	<key>PayloadIdentifier</key>
	<string>io.beeeye.mitm.profile.{{.ProfileUUID}}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{.ProfileUUID}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`))

// uuidFromHash formats 16 bytes of an already-random-looking hash (SHA-256
// of the cert DER, domain-separated by salt) as a UUID-shaped string. Not a
// real random UUID — deterministic on purpose, so the profile's identifiers
// stay stable across agent restarts instead of minting a new one, and
// re-installing shows as an update rather than a duplicate profile.
func uuidFromHash(sum []byte, salt string) string {
	h := sha256.Sum256(append(sum, salt...))
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// wrap76 line-wraps base64 at 76 columns, the convention plist/PEM data
// blocks use — not required by the parser, purely so the file is readable
// if anyone opens it.
func wrap76(s string) string {
	var buf bytes.Buffer
	for i := 0; i < len(s); i += 76 {
		end := i + 76
		if end > len(s) {
			end = len(s)
		}
		buf.WriteString(s[i:end])
		buf.WriteByte('\n')
	}
	return buf.String()
}
