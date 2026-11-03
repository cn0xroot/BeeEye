//go:build !linux

package tlspeek

import "errors"

type Library struct {
	Path   string
	Family string
	PIDs   []int
}

func FindLibraries() ([]Library, error) {
	return nil, errors.New("TLS library discovery requires Linux")
}
