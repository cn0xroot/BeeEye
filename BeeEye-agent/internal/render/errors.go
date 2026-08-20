package render

import "errors"

var errBadGeometry = errors.New("render: intensity buffer or output buffer does not match the requested geometry")
