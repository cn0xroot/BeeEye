package dissect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// GSMTAP is osmocom's de-facto standard for carrying a captured
// telecom-protocol frame over UDP (conventionally port 4729) so a tool like
// Wireshark can dissect it without needing the original air/bus interface.
// SIMtrace-family probes (which sniff the physical link between a phone and
// its SIM/USIM) use it to deliver ISO/IEC 7816-4 APDU traces — that is the
// one sub-protocol dissected in any depth here, since it is the one this
// analyzer has an offline-import use case for; other GSMTAP payload types
// are framed (header parsed, type named) but not decoded further.
//
// Header layout, 16 bytes (github.com/osmocom/libosmocore gsmtap.h):
//
//	version(1) hdr_len(1) type(1) timeslot(1)
//	arfcn(2) signal_dbm(1) snr_db(1)
//	frame_number(4)
//	sub_type(1) antenna_nr(1) sub_slot(1) res(1)
func dissectGSMTAP(r *Result, b []byte, off int) {
	p := b[off:]
	if len(p) < 16 {
		return
	}
	hdrLen := int(p[1]) * 4
	if hdrLen < 16 || hdrLen > len(p) {
		hdrLen = 16 // malformed hdr_len; 16 is what every real sender writes
	}
	typ := p[2]
	frameNr := binary.BigEndian.Uint32(p[8:12])

	r.proto("gsmtap")
	r.Proto = "GSMTAP"
	n := node("GSM TAP Header, Type: "+gsmtapTypeName(typ), off, hdrLen)
	r.leaf(n, "Type: "+gsmtapTypeName(typ), "gsmtap.type", gsmtapTypeName(typ), off+2, 1)
	r.leaf(n, "Frame Number", "gsmtap.frame_number", fmt.Sprintf("%d", frameNr), off+8, 4)
	r.layer(n, "gsmtap")

	if typ == gsmtapTypeSIM {
		dissectSIMApdu(r, b, off+hdrLen)
		return
	}
	r.Info = "GSMTAP " + gsmtapTypeName(typ)
}

const gsmtapTypeSIM = 0x04

// gsmtapTypeName covers the handful of GSMTAP payload types this codebase
// can actually attribute with confidence; anything else is shown as its raw
// number rather than a guessed name.
func gsmtapTypeName(t uint8) string {
	switch t {
	case 0x01:
		return "Um (GSM air interface)"
	case 0x02:
		return "Abis"
	case 0x03:
		return "Um burst"
	case 0x04:
		return "SIM"
	}
	return fmt.Sprintf("type 0x%02x", t)
}

// ISO/IEC 7816-4 instruction codes this dissector names. SELECT/READ
// BINARY/READ RECORD/UPDATE BINARY/UPDATE RECORD/GET RESPONSE are the base
// ISO 7816-4 set every smart card implements; VERIFY/CHANGE/UNBLOCK CHV,
// TERMINAL PROFILE/FETCH/TERMINAL RESPONSE/ENVELOPE/STATUS/RUN GSM ALGORITHM
// are the (U)SIM-specific instructions ETSI TS 102.221 and 3GPP TS 51.011 /
// 31.102 add on top.
const (
	simInsSelect       = 0xa4
	simInsReadBinary   = 0xb0
	simInsUpdateBinary = 0xd6
	simInsReadRecord   = 0xb2
	simInsUpdateRecord = 0xdc
	simInsVerify       = 0x20
	simInsUnblockChv   = 0x2c
)

func simInsName(ins byte) string {
	switch ins {
	case 0x04:
		return "DEACTIVATE FILE"
	case 0x10:
		return "TERMINAL PROFILE"
	case 0x12:
		return "FETCH"
	case 0x14:
		return "TERMINAL RESPONSE"
	case simInsVerify:
		return "VERIFY CHV"
	case 0x24:
		return "CHANGE CHV"
	case 0x26:
		return "DISABLE CHV"
	case 0x28:
		return "ENABLE CHV"
	case simInsUnblockChv:
		return "UNBLOCK CHV"
	case 0x32:
		return "INCREASE"
	case 0x70:
		return "MANAGE CHANNEL"
	case 0x88:
		return "RUN GSM ALGORITHM / AUTHENTICATE"
	case 0xa2:
		return "SEARCH RECORD"
	case simInsSelect:
		return "SELECT"
	case simInsReadBinary:
		return "READ BINARY"
	case simInsReadRecord:
		return "READ RECORD"
	case 0xc0:
		return "GET RESPONSE"
	case 0xc2:
		return "ENVELOPE"
	case simInsUpdateBinary:
		return "UPDATE BINARY"
	case simInsUpdateRecord:
		return "UPDATE RECORD"
	case 0xf2:
		return "STATUS"
	}
	return fmt.Sprintf("INS 0x%02x", ins)
}

// dissectSIMApdu parses one ISO/IEC 7816-4 command APDU — CLA INS P1 P2
// [Lc [Data]] — and, when present, a trailing SW1 SW2 status word.
//
// T=0's own procedure-byte exchange (a card can ask for data in pieces, or
// signal "more available, call GET RESPONSE") means a single isolated frame
// cannot always say with certainty where the command ends and a response
// begins; SIMtrace-family capture tools commonly report a full
// command-and-response pair in one GSMTAP frame, which is what the trailing
// "exactly 2 unaccounted-for bytes look like a status word" check below
// assumes. This does not track state across frames the way a live SIM
// session (or Wireshark's own gsm_sim dissector, which reassembles
// GET RESPONSE chains) can — it reports what one frame's own bytes support
// and nothing more.
func dissectSIMApdu(r *Result, b []byte, off int) {
	p := b[off:]
	r.proto("sim")
	r.Proto = "SIM"

	if len(p) == 2 {
		// Too short for a command; reads as a bare status word left over
		// from wherever this frame's capture boundary fell.
		sw := binary.BigEndian.Uint16(p)
		r.set("gsm_sim.apdu.sw", swName(sw))
		r.Info = "SW=" + swName(sw)
		return
	}
	if len(p) < 4 {
		return
	}

	cla, ins, p1, p2 := p[0], p[1], p[2], p[3]
	insName := simInsName(ins)
	cursor := 4
	var lc int
	var data []byte
	if cursor < len(p) {
		lc = int(p[cursor])
		if cursor+1+lc <= len(p) {
			data = p[cursor+1 : cursor+1+lc]
			cursor += 1 + lc
		}
		// A declared Lc running past what this frame actually captured is
		// left alone (lc/data untouched) rather than mis-slicing — happens
		// on a truncated/snaplen-limited capture.
	}

	n := node("ISO/IEC 7816-4 APDU: "+insName, off, len(p))
	r.leaf(n, "CLA", "gsm_sim.apdu.cla", fmt.Sprintf("0x%02x", cla), off, 1)
	r.leaf(n, "INS: "+insName, "gsm_sim.apdu.ins", insName, off+1, 1)
	r.leaf(n, "P1", "gsm_sim.apdu.p1", fmt.Sprintf("0x%02x", p1), off+2, 1)
	r.leaf(n, "P2", "gsm_sim.apdu.p2", fmt.Sprintf("0x%02x", p2), off+3, 1)

	info := insName
	switch ins {
	case simInsSelect:
		// P1 (Selection Control) says what kind of identifier follows, per
		// ETSI TS 102.221 §11.1.1 Table 11.3 — it is what actually
		// distinguishes "a 4-byte application ID" from "a path of two
		// 2-byte file IDs", which the data's own length/shape cannot.
		switch {
		case p1 == 0x04:
			// Select by AID (application selection, e.g. the USIM ADF) —
			// an arbitrary-length application identifier, not a
			// fixed-width file ID this table can name.
			aid := fmt.Sprintf("%x", data)
			r.leaf(n, "Application ID", "gsm_sim.aid", aid, off+cursor-len(data), len(data))
			info = "SELECT AID=" + aid
		case len(data) >= 2 && len(data)%2 == 0:
			// Select by file ID (P1 0x00) or by path (P1 0x08/0x09) — either
			// way, a sequence of one or more 2-byte file IDs from MF or the
			// current DF; a bare file ID is just a one-element path.
			names := make([]string, 0, len(data)/2)
			for i := 0; i+2 <= len(data); i += 2 {
				names = append(names, simFileName(binary.BigEndian.Uint16(data[i:i+2])))
			}
			path := strings.Join(names, "/")
			r.leaf(n, "File: "+path, "gsm_sim.file_id", path, off+cursor-len(data), len(data))
			info = "SELECT " + path
		}
	case simInsReadBinary:
		info = fmt.Sprintf("READ BINARY Offset=%d", int(p1)<<8|int(p2))
	case simInsUpdateBinary:
		info = fmt.Sprintf("UPDATE BINARY Offset=%d", int(p1)<<8|int(p2))
	case simInsReadRecord:
		info = fmt.Sprintf("READ RECORD RecordNr=%d", p1)
	case simInsUpdateRecord:
		info = fmt.Sprintf("UPDATE RECORD RecordNr=%d", p1)
	case simInsVerify:
		info = fmt.Sprintf("VERIFY CHV=%d", p2&0x0f)
	case simInsUnblockChv:
		info = fmt.Sprintf("UNBLOCK CHV=%d", p2&0x0f)
	}

	// Exactly 2 bytes left over after everything this dissector otherwise
	// accounted for reads as the card's status word — see the doc comment.
	if len(p)-cursor == 2 {
		sw := binary.BigEndian.Uint16(p[cursor:])
		r.leaf(n, "Status Word: "+swName(sw), "gsm_sim.apdu.sw", swName(sw), off+cursor, 2)
		info += " : " + swName(sw)
	}

	r.layer(n, "sim")
	r.Info = info
}

// swName renders an ISO/IEC 7816-4 §5.1.3 / ETSI TS 102.221 §10.2.1 status
// word. The exact codes below are the ones defined precisely; SW1-only
// fallbacks cover the defined *classes* (a warning, a security condition,
// wrong parameters, …) honestly rather than inventing a specific meaning a
// card-family/command-specific extension might actually assign that byte.
func swName(sw uint16) string {
	switch sw {
	case 0x9000:
		return "normal ending"
	case 0x6a82:
		return "file not found"
	case 0x6a86:
		return "incorrect P1/P2"
	case 0x6a88:
		return "referenced data not found"
	case 0x6700:
		return "wrong length"
	case 0x6982:
		return "security status not satisfied"
	case 0x6985:
		return "conditions of use not satisfied"
	case 0x6d00:
		return "instruction code not supported"
	case 0x6e00:
		return "class not supported"
	case 0x6f00:
		return "technical problem, no precise diagnosis"
	}
	sw1, sw2 := byte(sw>>8), byte(sw)
	switch sw1 {
	case 0x61:
		return fmt.Sprintf("%d byte(s) of response data available (GET RESPONSE)", sw2)
	case 0x91:
		return fmt.Sprintf("normal ending, proactive command pending (%d bytes)", sw2)
	case 0x92:
		return "normal ending, memory management"
	case 0x93:
		return "SIM Application Toolkit busy"
	case 0x94:
		return "command error"
	case 0x63:
		if sw2&0xf0 == 0xc0 {
			return fmt.Sprintf("PIN check failed, %d attempt(s) remaining", sw2&0x0f)
		}
		return "warning: memory unchanged"
	case 0x62:
		return "warning: memory unchanged"
	case 0x69:
		return "command not allowed"
	case 0x6a, 0x6b:
		return "wrong parameters"
	}
	return fmt.Sprintf("0x%04x", sw)
}

// simFileName maps a (U)SIM elementary/dedicated file ID to its standard
// short name, per ETSI TS 102.221 and 3GPP TS 31.102/51.011 — the same
// table Wireshark's own gsm_sim dissector draws from, so a file this
// analyzer names and a file Wireshark names are never in disagreement. Not
// exhaustive: an ID outside this table is shown as its raw hex value rather
// than a guessed name.
func simFileName(id uint16) string {
	if name, ok := simFileNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}

var simFileNames = map[uint16]string{
	0x3f00: "MF",
	0x7f10: "DF.TELECOM",
	0x7f20: "DF.GSM",
	0x7fff: "ADF",
	0x5f3a: "DF.PHONEBOOK",
	0x5fc0: "DF.5GS",

	0x2f00: "EF.DIR",
	0x2f05: "EF.ELP",
	0x2fe2: "EF.ICCID",

	0x4f07: "EF.SUCI_Calc_Info",
	0x4f30: "EF.PBR",
	0x4f3a: "EF.ADN",
	0x4f3b: "EF.ADN1",

	0x6f02: "EF.5GSnon3GPPAccessNASSecCtxt",
	0x6f05: "EF.LP",
	0x6f07: "EF.IMSI",
	0x6f08: "EF.Keys",
	0x6f09: "EF.KeysPS",
	0x6f31: "EF.HPPLMN",
	0x6f38: "EF.SST",
	0x6f3b: "EF.FDN",
	0x6f3c: "EF.SMS",
	0x6f3e: "EF.GID1",
	0x6f3f: "EF.GID2",
	0x6f40: "EF.MSISDN",
	0x6f42: "EF.SMSP",
	0x6f43: "EF.SMSS",
	0x6f45: "EF.CBMI",
	0x6f46: "EF.SPN",
	0x6f48: "EF.CBMID",
	0x6f49: "EF.SDN",
	0x6f4b: "EF.EXT2",
	0x6f4c: "EF.EXT3",
	0x6f56: "EF.EST",
	0x6f5b: "EF.START-HFN",
	0x6f5c: "EF.THRESHOLD",
	0x6f60: "EF.PLMNwAcT",
	0x6f61: "EF.OPLMNwAcT",
	0x6f62: "EF.HPLMNAcT",
	0x6f73: "EF.PSLOCI",
	0x6f78: "EF.ACC",
	0x6f7b: "EF.FPLMN",
	0x6f7e: "EF.LOCI",
	0x6fad: "EF.AD",
	0x6fb7: "EF.ECC",
	0x6fc4: "EF.NETPAR",
	0x6fc5: "EF.PNN",
	0x6fc6: "EF.OPL",
	0x6fc7: "EF.MBDN",
	0x6fc9: "EF.MBI",
	0x6fcb: "EF.CFIS",
	0x6fcd: "EF.SPDI",
	0x6fd9: "EF.EHPLMN",
	0x6fe3: "EF.EPSLOCI",
	0x6fe4: "EF.EPSNSC",
}
