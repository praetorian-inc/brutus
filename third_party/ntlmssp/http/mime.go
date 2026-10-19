package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/tidwall/transform"
)

const (
	mimeBoundary      string = "Encrypted Boundary"
	mimeProtocol      string = "application/HTTP-SPNEGO-session-encrypted"
	dashBoundary      string = "--" + mimeBoundary
	contentTypeHeader string = "Content-Type"
	contentTypeValue  string = "multipart/encrypted;protocol=\"" + mimeProtocol + "\";boundary=\"" + mimeBoundary + "\""
	octetStream       string = "application/octet-stream"
)

func isHeader(line []byte) bool {
	b := make([]byte, len(line))
	copy(b, line)
	b = append(b, '\r', '\n')
	r := textproto.NewReader(bufio.NewReader(bytes.NewBuffer(b)))
	_, err := r.ReadMIMEHeader()
	if err != nil {
		return false
	}
	return true
}

func toWSMV(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	return transform.NewTransformer(func() ([]byte, error) {
		for {
			line, err := br.ReadBytes('\n')
			if err != nil {
				return nil, err
			}

			switch {
			case bytes.Equal(line, []byte{'\r', '\n'}):
				break
			case bytes.HasPrefix(line, []byte(dashBoundary)):
				return line, nil
			case isHeader(line):
				return append([]byte{'\t'}, line...), nil
			default:
				next, err := br.Peek(len(dashBoundary))
				if err != nil {
					return nil, err
				}
				if bytes.Equal(next, []byte(dashBoundary)) {
					return line[:len(line)-2], nil
				}
				return line, nil
			}
		}
	})
}

func fromWSMV(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	header := false
	return transform.NewTransformer(func() ([]byte, error) {
		for {
			line, err := br.ReadBytes('\n')
			if err != nil {
				return nil, err
			}

			switch {
			case bytes.HasPrefix(line, []byte{'\t'}) && isHeader(line[1:]):
				header = true
				return line[1:], nil
			default:
				if header {
					line = append([]byte{'\r', '\n'}, line...)
					header = false
				}
				if bytes.Contains(line[1:], []byte(dashBoundary)) {
					for i := 0; i < len(line); i++ {
						if bytes.HasPrefix(line[i:], []byte(dashBoundary)) {
							line = append(line[:i], append([]byte{'\r', '\n'}, line[i:]...)...)
							break
						}
					}
				}
				return line, nil
			}
		}
	})
}

func Wrap(input []byte, ct string) ([]byte, string, error) {
	b := &bytes.Buffer{}

	writer := multipart.NewWriter(b)
	if err := writer.SetBoundary(mimeBoundary); err != nil {
		return nil, "", err
	}

	header := make(textproto.MIMEHeader)
	header.Set(contentTypeHeader, mimeProtocol)
	// Using Set() will canonicalise this to "Originalcontent" which may cause problems
	header["OriginalContent"] = []string{fmt.Sprintf("type=%s;Length=%d", ct, len(input))}

	if _, err := writer.CreatePart(header); err != nil {
		return nil, "", err
	}

	body := make(textproto.MIMEHeader)
	body.Set(contentTypeHeader, octetStream)

	part, err := writer.CreatePart(body)
	if err != nil {
		return nil, "", err
	}

	if _, err := io.Copy(part, bytes.NewBuffer(input)); err != nil {
		return nil, "", err
	}

	writer.Close()

	output, err := ioutil.ReadAll(toWSMV(b))
	if err != nil {
		return nil, "", err
	}

	return output, contentTypeValue, nil
}

func Unwrap(input []byte, ct string) ([]byte, string, error) {
	if ct != contentTypeValue {
		return nil, "", errors.New("incorrect Content-Type value")
	}

	reader := multipart.NewReader(fromWSMV(bytes.NewBuffer(input)), mimeBoundary)
	output := bytes.Buffer{}

	var originalContent string

Loop:
	for i := 0; true; i++ {
		part, err := reader.NextPart()
		switch err {
		case nil:
			break
		case io.EOF:
			break Loop
		default:
			return nil, "", err
		}

		switch i {
		case 0:
			if part.Header.Get(contentTypeHeader) != mimeProtocol {
				return nil, "", errors.New("incorrect Content-Type value")
			}
			if originalContent = part.Header.Get("OriginalContent"); originalContent == "" {
				return nil, "", errors.New("missing OriginalContent header")
			}
		case 1:
			if part.Header.Get(contentTypeHeader) != octetStream {
				return nil, "", errors.New("incorrect Content-Type value")
			}
			if _, err := output.ReadFrom(part); err != nil {
				return nil, "", err
			}
		default:
			return nil, "", errors.New("additional MIME parts encountered")
		}
	}

	// TODO Better way of parsing this
	parts := strings.Split(originalContent, ";")

	return output.Bytes(), parts[0][5:] + ";" + parts[1], nil
}
