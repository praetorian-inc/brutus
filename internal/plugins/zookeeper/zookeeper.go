// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zookeeper

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	defaultPort = "2181"
	opAddAuth   = 100
	opExists    = 3
)

var zkAuthIndicators = []string{
	"authentication failed",
	"not authenticated",
	"authfailed",
	"session expired",
}

func init() {
	brutus.Register("zookeeper", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "zookeeper" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("zookeeper", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	conn, err := dial(ctx, target, timeout, pluginCfg)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	if err := sendConnect(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if _, err := readConnect(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	digest := username + ":" + zkDigest(username, password)
	if err := sendAddAuth(conn, []byte(digest)); err != nil {
		result.Error = classifyError(err)
		return result
	}
	xid, errCode, err := readResponse(conn)
	_ = xid
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	if errCode == 0 {
		result.Success = true
		return result
	}
	if errCode == -102 || errCode == -115 {
		return result
	}
	result.Error = fmt.Errorf("connection error: zookeeper err %d", errCode)
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("zookeeper", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, "envi"); err != nil {
		return result
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return result
	}
	if strings.Contains(strings.ToLower(line), "zookeeper") || strings.Contains(line, "Environment") {
		result.Success = true
		result.Banner = "[CRITICAL] ZooKeeper accessible without authentication"
	}
	return result
}

func dial(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) (net.Conn, error) {
	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func sendConnect(w io.Writer) error {
	buf := make([]byte, 44)
	binary.BigEndian.PutUint32(buf[0:4], 40)
	binary.BigEndian.PutUint32(buf[4:8], 0)
	binary.BigEndian.PutUint64(buf[12:20], 0)
	binary.BigEndian.PutUint32(buf[20:24], 30000)
	binary.BigEndian.PutUint64(buf[24:32], 0)
	binary.BigEndian.PutUint32(buf[32:36], 16)
	copy(buf[36:44], []byte("brutuszk"))
	_, err := w.Write(buf)
	return err
}

func readConnect(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n > 1<<16 {
		return nil, fmt.Errorf("zookeeper connect reply too large")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return body, err
}

func sendAddAuth(w io.Writer, digest []byte) error {
	scheme := []byte("digest")
	n := 4 + 4 + 4 + len(scheme) + 4 + len(digest)
	buf := make([]byte, 4+n)
	binary.BigEndian.PutUint32(buf[0:4], uint32(n))
	binary.BigEndian.PutUint32(buf[4:8], 1)
	binary.BigEndian.PutUint32(buf[8:12], opAddAuth)
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(scheme)))
	copy(buf[16:], scheme)
	off := 16 + len(scheme)
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(digest)))
	copy(buf[off+4:], digest)
	_, err := w.Write(buf)
	return err
}

func readResponse(r io.Reader) (xid, errCode int32, err error) {
	var n uint32
	if err = binary.Read(r, binary.BigEndian, &n); err != nil {
		return
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(r, body); err != nil {
		return
	}
	if len(body) < 16 {
		err = fmt.Errorf("short zk response")
		return
	}
	xid = int32(binary.BigEndian.Uint32(body[0:4]))
	errCode = int32(binary.BigEndian.Uint32(body[12:16]))
	return
}

func zkDigest(user, pass string) string {
	sum := sha1.Sum([]byte(user + ":" + pass))
	return base64.StdEncoding.EncodeToString(sum[:])
}

var classifyError = brutus.NewClassifier(zkAuthIndicators)
