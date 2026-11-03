//go:build darwin

package live

import (
	"encoding/binary"
	"reflect"
	"testing"
	"time"
)

// mkRec 构造一条 bpf_hdr+数据记录(含 4 字节对齐填充)。
func mkRec(sec, usec int32, data []byte, datalen int) []byte {
	ne := binary.NativeEndian
	h := make([]byte, 18)
	ne.PutUint32(h[0:], uint32(sec))
	ne.PutUint32(h[4:], uint32(usec))
	ne.PutUint32(h[8:], uint32(len(data)))
	ne.PutUint32(h[12:], uint32(datalen))
	ne.PutUint16(h[16:], 18)
	r := append(h, data...)
	for len(r)%4 != 0 {
		r = append(r, 0)
	}
	return r
}

func TestParseBPFBufferEthernet(t *testing.T) {
	f1 := []byte{1, 2, 3, 4, 5} // 奇数长度,检验对齐
	f2 := []byte{9, 8, 7}
	buf := append(mkRec(100, 500, f1, 1500), mkRec(101, 0, f2, 3)...)
	var got [][]byte
	var lens []int
	var ts []time.Time
	parseBPFBuffer(buf, dltEN10, "en0", func(t time.Time, d []byte, ol int) {
		got = append(got, d)
		lens = append(lens, ol)
		ts = append(ts, t)
	})
	if !reflect.DeepEqual(got, [][]byte{f1, f2}) {
		t.Fatalf("frames = %v", got)
	}
	if lens[0] != 1500 || lens[1] != 3 {
		t.Errorf("origLen = %v", lens)
	}
	if !ts[0].Equal(time.Unix(100, 500000)) {
		t.Errorf("ts = %v", ts[0])
	}
}

func TestParseBPFBufferNullLinkBecomesEthernet(t *testing.T) {
	ne := binary.NativeEndian
	for _, c := range []struct {
		af   uint32
		want [2]byte
	}{{2, [2]byte{0x08, 0x00}}, {afInet6D, [2]byte{0x86, 0xDD}}} {
		pay := []byte{0x45, 0, 0, 20}
		d := make([]byte, 4)
		ne.PutUint32(d, c.af)
		d = append(d, pay...)
		var out []byte
		var ol int
		parseBPFBuffer(mkRec(1, 0, d, len(d)), dltNull, "lo0", func(_ time.Time, b []byte, o int) { out, ol = b, o })
		if len(out) != 14+len(pay) || out[12] != c.want[0] || out[13] != c.want[1] || !reflect.DeepEqual(out[14:], pay) {
			t.Errorf("af=%d out=%v", c.af, out)
		}
		if ol != len(d)+10 {
			t.Errorf("origLen = %d", ol)
		}
	}
}

func TestParseBPFBufferTruncated(t *testing.T) {
	buf := mkRec(1, 0, []byte{1, 2, 3, 4}, 4)
	n := 0
	parseBPFBuffer(buf[:20], dltEN10, "en0", func(time.Time, []byte, int) { n++ })
	if n != 0 {
		t.Errorf("truncated record emitted %d frames", n)
	}
}

func TestDiffLinks(t *testing.T) {
	prev := map[string]bool{"en0": true, "en5": true, "utun1": false}
	cur := map[string]bool{"en0": true, "en7": true, "utun1": true}
	got := diffLinks(prev, cur)
	want := []LinkEvent{{Name: "en5", Removed: true}, {Name: "en7"}, {Name: "utun1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
