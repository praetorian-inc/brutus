package http

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/bodgit/ntlmssp"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-cleanhttp"
)

var (
	httpAuthenticateHeader = textproto.CanonicalMIMEHeaderKey("WWW-Authenticate")
)

type Client struct {
	http       *http.Client
	ntlm       *ntlmssp.Client
	encryption bool
	sendCBT    bool
	logger     logr.Logger
}

type teeReadCloser struct {
	io.Reader
	io.Closer
}

func NewClient(httpClient *http.Client, ntlmClient *ntlmssp.Client, options ...func(*Client) error) (*Client, error) {
	if httpClient == nil {
		httpClient = cleanhttp.DefaultClient()
	}
	if httpClient.Jar == nil {
		httpClient.Jar, _ = cookiejar.New(nil)
	}
	if httpClient.Transport != nil && httpClient.Transport.(*http.Transport).DisableKeepAlives {
		return nil, errors.New("NTLM cannot work without keepalives")
	}

	// FIXME CheckRedirect

	if ntlmClient == nil {
		domain, err := ntlmssp.DefaultDomain()
		if err != nil {
			return nil, err
		}

		workstation, err := ntlmssp.DefaultWorkstation()
		if err != nil {
			return nil, err
		}

		ntlmClient, _ = ntlmssp.NewClient(ntlmssp.SetDomain(domain), ntlmssp.SetWorkstation(workstation), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	}

	c := &Client{
		http:   httpClient,
		ntlm:   ntlmClient,
		logger: logr.Discard(),
	}

	if err := c.SetOption(options...); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) SetOption(options ...func(*Client) error) error {
	for _, option := range options {
		if err := option(c); err != nil {
			return err
		}
	}
	return nil
}

func SendCBT(value bool) func(*Client) error {
	return func(c *Client) error {
		c.sendCBT = value
		return nil
	}
}

func Encryption(value bool) func(*Client) error {
	return func(c *Client) error {
		c.encryption = value
		return nil
	}
}

func Logger(logger logr.Logger) func(*Client) error {
	return func(c *Client) error {
		c.logger = logger
		return nil
	}
}

func (c *Client) wrap(req *http.Request) error {
	if session := c.ntlm.SecuritySession(); c.ntlm.Complete() && c.encryption && session != nil && req.Body != nil {

		contentType := req.Header.Get(contentTypeHeader)
		if contentType == "" {
			return errors.New("no Content-Type header")
		}

		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}

		sealed, signature, err := session.Wrap(body)
		if err != nil {
			return err
		}

		length := make([]byte, 4)
		binary.LittleEndian.PutUint32(length, uint32(len(signature)))

		body, newContentType, err := Wrap(concat(length, signature, sealed), contentType)
		if err != nil {
			return err
		}

		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		req.Header.Set(contentTypeHeader, newContentType)
	}

	return nil
}

func (c *Client) unwrap(resp *http.Response) error {
	if session := c.ntlm.SecuritySession(); c.ntlm.Complete() && c.encryption && session != nil && resp.Body != nil {

		contentType := resp.Header.Get(contentTypeHeader)
		if contentType == "" {
			return errors.New("no Content-Type header")
		}

		sealed, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		data, newContentType, err := Unwrap(sealed, contentType)
		if err != nil {
			return err
		}

		length := binary.LittleEndian.Uint32(data[:4])

		signature := make([]byte, length)
		copy(signature, data[4:4+length])

		body, err := session.Unwrap(data[4+length:], signature)
		if err != nil {
			return err
		}

		resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		resp.Header.Set(contentTypeHeader, newContentType)
		resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
	}

	return nil
}

func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {

	// Potentially replace the request body with a signed and sealed copy
	if err := c.wrap(req); err != nil {
		return nil, err
	}

	var body bytes.Buffer

	if req.Body != nil {
		tr := io.TeeReader(req.Body, &body)
		req.Body = teeReadCloser{tr, req.Body}
	}

	c.logger.Info("request", req)

	resp, err = c.http.Do(req)
	if err != nil {
		return nil, err
	}

	if c.ntlm.Complete() || resp.StatusCode != http.StatusUnauthorized {
		// Potentially unseal and check signature
		if err := c.unwrap(resp); err != nil {
			return nil, err
		}

		return resp, nil
	}

	for i := 0; i < 2; i++ {

		ok, input, err := isAuthenticationMethod(resp.Header, "Negotiate")
		if err != nil {
			return nil, err
		}

		if !ok {
			return resp, nil
		}

		var cbt *ntlmssp.ChannelBindings

		if c.sendCBT && resp.TLS != nil {
			cbt = generateChannelBindings(resp.TLS.PeerCertificates[0]) // Presume it's the first one?
		}

		b, err := c.ntlm.Authenticate(input, cbt)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(b))

		if req.Body != nil {
			req.Body = ioutil.NopCloser(&body)
		}

		c.logger.Info("request", req)

		resp, err = c.http.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusUnauthorized {
			return resp, nil
		}
	}

	return resp, nil
}

func isAuthenticationMethod(headers http.Header, method string) (bool, []byte, error) {
	if h, ok := headers[httpAuthenticateHeader]; ok {
		for _, x := range h {
			if x == method {
				return true, nil, nil
			}
			if strings.HasPrefix(x, method+" ") {
				parts := strings.SplitN(x, " ", 2)
				if len(parts) < 2 {
					return true, nil, errors.New("malformed " + method + " header value")
				}
				b, err := base64.StdEncoding.DecodeString(parts[1])
				return true, b, err
			}
		}
	}
	return false, nil, nil
}

func (c *Client) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Head(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
