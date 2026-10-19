package proto

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// maxDecompressed bounds decompressed bodies (decompression bombs).
const maxDecompressed = 64 << 20

var zstdDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxDecompressed))

// decompress undoes HTTP content codings ("gzip", "br", "deflate",
// "zstd", or a comma-separated chain applied in order).
func decompress(encoding string, data []byte) ([]byte, error) {
	codings := strings.Split(encoding, ",")
	out := data
	for i := len(codings) - 1; i >= 0; i-- {
		c := strings.ToLower(strings.TrimSpace(codings[i]))
		var r io.Reader
		switch c {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(bytes.NewReader(out))
			if err != nil {
				return nil, err
			}
			r = zr
		case "deflate":
			// Servers send either zlib-wrapped or raw deflate.
			if zr, err := zlib.NewReader(bytes.NewReader(out)); err == nil {
				r = zr
			} else {
				r = flate.NewReader(bytes.NewReader(out))
			}
		case "br":
			r = brotli.NewReader(bytes.NewReader(out))
		case "zstd":
			b, err := zstdDec.DecodeAll(out, nil)
			if err != nil {
				return nil, err
			}
			out = b
			continue
		default:
			return nil, fmt.Errorf("unsupported content coding %q", c)
		}
		b, err := io.ReadAll(io.LimitReader(r, maxDecompressed))
		if err != nil && len(b) == 0 {
			return nil, err
		}
		out = b
	}
	return out, nil
}

// inflateRaw decompresses raw DEFLATE data (WebSocket permessage-deflate).
func inflateRaw(data []byte, dict []byte) ([]byte, error) {
	r := flate.NewReaderDict(bytes.NewReader(append(append([]byte(nil), data...), 0, 0, 0xff, 0xff)), dict)
	b, err := io.ReadAll(io.LimitReader(r, maxDecompressed))
	if err != nil && err != io.ErrUnexpectedEOF && len(b) == 0 {
		return nil, err
	}
	return b, nil
}
