package jsonutil

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"bytes"
	"io"

	jsoniter "github.com/json-iterator/go"
)

// AppendJoinLines appends src to dst omitting new lines ('\n').
// It can be used for removing new lines from a jsoniter.RawMessage so it can safely be used in JSONL.
// It is safe to use tha same buffer as dest and src to remove new lines in-place:
// ```go
// ```
func AppendJoinLines(dst, src []byte) []byte {
	const newLine = '\n'
	for len(src) > 0 {
		if pos := bytes.IndexByte(src, newLine); 0 <= pos && pos < len(src) {
			dst, src = append(dst, src[:pos]...), src[pos+1:]
		} else {
			return append(dst, src...)
		}
	}
	return dst
}

type EncoderJSONL struct {
	stream *jsoniter.Stream
	buffer AppendWriter
	n      int
	w      io.Writer
}

func NewEncoderJSONL(w io.Writer, api jsoniter.API) *EncoderJSONL {
	if api == nil {
		api = jsoniter.ConfigDefault
	}
	encoder := EncoderJSONL{
		w: w,
	}
	encoder.stream = jsoniter.NewStream(api, &encoder.buffer, 4096)
	return &encoder
}

func (e *EncoderJSONL) Encode(val interface{}) error {
	if err := e.stream.Error; err != nil {
		return err
	}
	e.buffer.Reset()
	e.stream.WriteVal(val)
	if err := e.stream.Flush(); err != nil {
		return err
	}
	if err := e.incr(); err != nil {
		return err
	}
	// Strip new lines in-place
	e.buffer.B = AppendJoinLines(e.buffer.B[:0], e.buffer.B)
	if _, err := e.w.Write(e.buffer.B); err != nil {
		return err
	}
	return nil
}

func (e *EncoderJSONL) NumLines() int {
	return e.n
}

func (e *EncoderJSONL) Reset(w io.Writer) {
	e.stream.Reset(&e.buffer)
	e.buffer.Reset()
	*e = EncoderJSONL{
		buffer: e.buffer,
		stream: e.stream,
		w:      w,
	}
}

func (e *EncoderJSONL) incr() error {
	if e.n > 0 {
		if _, err := e.w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	e.n++
	return nil
}

type AppendWriter struct {
	B []byte
}

func (w *AppendWriter) Reset() {
	w.B = w.B[:0]
}

func (w *AppendWriter) Write(p []byte) (int, error) {
	w.B = append(w.B, p...)
	return len(p), nil
}
func (w *AppendWriter) WriteByte(b byte) error {
	w.B = append(w.B, b)
	return nil
}
func (w *AppendWriter) WriteString(s string) (int, error) {
	w.B = append(w.B, s...)
	return len(s), nil
}
