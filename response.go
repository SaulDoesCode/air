package air

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/json-iterator/go"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/net/html"
)

// Response is an HTTP response.
type Response struct {
	Status        int
	Headers       map[string]*Header
	ContentLength int64
	Body          io.Writer
	Cookies       map[string]*Cookie
	Written       bool

	request *Request
	Writer  http.ResponseWriter
}

// Header get a Header if it exists
func (r *Response) Header(name string) (string, bool) {
	val, ok := r.Headers[name]
	if ok {
		return val.Value(), ok
	}
	return "", ok
}

// SetHeader adds a header to the response
func (r *Response) SetHeader(name string, values ...string) {
	r.Headers[name] = &Header{Name: name, Values: values}
}

// SetHeaderValues adds a header to the response with an array of string values
func (r *Response) SetHeaderValues(name string, values []string) {
	r.Headers[name] = &Header{Name: name, Values: values}
}

// SetCookie adds a Set-Cookie header to the ResponseWriter's headers.
// The provided cookie must have a valid Name. Invalid cookies may be
// silently dropped.
func (r *Response) SetCookie(name string, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	if path == "" {
		path = "/"
	}

	http.SetCookie(r.Writer, &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
	})
}

// Write responds to the client with the content.
func (r *Response) Write(content io.ReadSeeker) error {
	if r.Written {
		return nil
	}

	canWrite := false
	var reader io.Reader = content
	defer func() {
		if !canWrite {
			return
		}

		if HTTPSEnforced {
			r.SetHeader("strict-transport-security", "max-age=31536000")
		}

		if reader != nil && r.ContentLength == 0 {
			r.ContentLength, _ = content.Seek(0, io.SeekEnd)
			content.Seek(0, io.SeekStart)
		}

		if r.Status >= 200 && r.Status < 400 {
			r.SetHeader("accept-ranges", "bytes")
		}

		if r.ContentLength >= 0 &&
			r.Headers["transfer-encoding"].Value() == "" &&
			r.Status >= 200 &&
			r.Status != 204 &&
			(r.Status >= 300 || r.request.Method != "CONNECT") {
			r.SetHeader("content-length", strconv.FormatInt(r.ContentLength, 10))
		}

		if len(r.Cookies) > 0 {
			vs := make([]string, 0, len(r.Cookies))
			for _, c := range r.Cookies {
				vs = append(vs, c.String())
			}

			r.SetHeaderValues("set-cookie", vs)
		}

		for n, h := range r.Headers {
			n := textproto.CanonicalMIMEHeaderKey(n)
			r.Writer.Header()[n] = h.Values
		}

		r.Writer.WriteHeader(r.Status)
		if r.request.Method != "HEAD" {
			io.CopyN(r.Writer, reader, r.ContentLength)
		}

		r.Written = true
	}()

	if r.Status >= 400 { // Something has gone wrong
		canWrite = true
		return nil
	}

	im := r.request.Headers["if-match"].Value()
	et := r.Headers["etag"].Value()
	ius, _ := http.ParseTime(
		r.request.Headers["if-unmodified-since"].Value(),
	)
	lm, _ := http.ParseTime(r.Headers["last-modified"].Value())
	if im != "" {
		matched := false
		for {
			im = textproto.TrimString(im)
			if len(im) == 0 {
				break
			}

			if im[0] == ',' {
				im = im[1:]
				continue
			}

			if im[0] == '*' {
				matched = true
				break
			}

			eTag, remain := scanETag(im)
			if eTag == "" {
				break
			}

			if eTagStrongMatch(eTag, et) {
				matched = true
				break
			}

			im = remain
		}

		if !matched {
			r.Status = 412
		}
	} else if !ius.IsZero() && !lm.Before(ius.Add(time.Second)) {
		r.Status = 412
	}

	inm := r.request.Headers["if-none-match"].Value()
	ims, _ := http.ParseTime(
		r.request.Headers["if-modified-since"].Value(),
	)
	if inm != "" {
		noneMatched := true
		for {
			inm = textproto.TrimString(inm)
			if len(inm) == 0 {
				break
			}

			if inm[0] == ',' {
				inm = inm[1:]
			}

			if inm[0] == '*' {
				noneMatched = false
				break
			}

			eTag, remain := scanETag(inm)
			if eTag == "" {
				break
			}

			if eTagWeakMatch(eTag, r.Headers["etag"].Value()) {
				noneMatched = false
				break
			}

			inm = remain
		}
		if !noneMatched {
			if r.request.Method == "GET" ||
				r.request.Method == "HEAD" {
				r.Status = 304
			} else {
				r.Status = 412
			}
		}
	} else if !ims.IsZero() && lm.Before(ims.Add(time.Second)) {
		r.Status = 304
	}

	if r.Status == 304 {
		delete(r.Headers, "content-type")
		delete(r.Headers, "content-length")
		canWrite = true
		return nil
	} else if r.Status == 412 {
		return errors.New("precondition failed")
	} else if content == nil {
		canWrite = true
		return nil
	}

	ct := r.Headers["content-type"].Value()
	if ct == "" {
		// Read a chunk to decide between UTF-8 text and binary
		b := [1 << 9]byte{}
		n, _ := io.ReadFull(content, b[:])
		ct = http.DetectContentType(b[:n])
		if _, err := content.Seek(0, io.SeekStart); err != nil {
			return err
		}

		r.SetHeader("content-type", ct)
	}

	size, err := content.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	} else if _, err := content.Seek(0, io.SeekStart); err != nil {
		return err
	}

	r.ContentLength = size

	rh := r.request.Headers["range"].Value()
	if rh == "" {
		canWrite = true
		return nil
	} else if r.request.Method == "GET" || r.request.Method == "HEAD" {
		if ir := r.request.Headers["if-range"].Value(); ir != "" {
			if eTag, _ := scanETag(ir); eTag != "" &&
				!eTagStrongMatch(eTag, et) {
				canWrite = true
				return nil
			}

			// The If-Range value is typically the ETag value, but
			// it may also be the modtime date. See
			// golang.org/issue/8367.
			if lm.IsZero() {
				canWrite = true
				return nil
			} else if t, _ := http.ParseTime(ir); !t.Equal(lm) {
				canWrite = true
				return nil
			}
		}
	}

	const b = "bytes="
	if !strings.HasPrefix(rh, b) {
		r.Status = 416
		return errors.New("invalid range")
	}

	ranges := []httpRange{}
	noOverlap := false
	for _, ra := range strings.Split(rh[len(b):], ",") {
		ra = strings.TrimSpace(ra)
		if ra == "" {
			continue
		}

		i := strings.Index(ra, "-")
		if i < 0 {
			r.Status = 416
			return errors.New("invalid range")
		}

		start := strings.TrimSpace(ra[:i])
		end := strings.TrimSpace(ra[i+1:])
		hr := httpRange{}
		if start == "" {
			// If no start is specified, end specifies the
			// range start relative to the end of the file.
			i, err := strconv.ParseInt(end, 10, 64)
			if err != nil {
				r.Status = 416
				return errors.New("invalid range")
			}

			if i > size {
				i = size
			}

			hr.start = size - i
			hr.length = size - hr.start
		} else {
			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i < 0 {
				r.Status = 416
				return errors.New("invalid range")
			}

			if i >= size {
				// If the range begins after the size of the
				// content, then it does not overlap.
				noOverlap = true
				continue
			}

			hr.start = i
			if end == "" {
				// If no end is specified, range extends to end
				// of the file.
				hr.length = size - hr.start
			} else {
				i, err := strconv.ParseInt(end, 10, 64)
				if err != nil || hr.start > i {
					r.Status = 416
					return errors.New("invalid range")
				}

				if i >= size {
					i = size - 1
				}

				hr.length = i - hr.start + 1
			}
		}

		ranges = append(ranges, hr)
	}

	if noOverlap && len(ranges) == 0 {
		// The specified ranges did not overlap with the content.
		r.SetHeader("content-range", fmt.Sprintf("bytes */%d", size))
		r.Status = 416

		return errors.New("invalid range: failed to overlap")
	}

	var rangesSize int64
	for _, ra := range ranges {
		rangesSize += ra.length
	}

	if rangesSize > size {
		ranges = nil
	}

	if l := len(ranges); l == 1 {
		// RFC 2616, section 14.16:
		// "When an HTTP message includes the content of a single range
		// (for example, a response to a request for a single range, or
		// to a request for a set of ranges that overlap without any
		// holes), this content is transmitted with a Content-Range
		// header, and a Content-Length header showing the number of
		// bytes actually transferred.
		// ...
		// A response to a request for a single range MUST NOT be sent
		// using the multipart/byteranges media type."
		ra := ranges[0]
		if _, err := content.Seek(ra.start, io.SeekStart); err != nil {
			r.Status = 416
			return err
		}

		r.ContentLength = ra.length
		r.Status = 206
		r.SetHeader("content-range", ra.contentRange(size))
	} else if l > 1 {
		var w countingWriter
		mw := multipart.NewWriter(&w)
		for _, ra := range ranges {
			mw.CreatePart(ra.header(ct, size))
			r.ContentLength += ra.length
		}

		mw.Close()
		r.ContentLength += int64(w)

		r.Status = 206

		pr, pw := io.Pipe()
		mw = multipart.NewWriter(pw)

		r.SetHeader("content-type", "multipart/byteranges; boundary="+mw.Boundary())

		reader = pr
		defer pr.Close()
		go func() {
			for _, ra := range ranges {
				part, err := mw.CreatePart(ra.header(ct, size))
				if err != nil {
					pw.CloseWithError(err)
					return
				}

				if _, err := content.Seek(
					ra.start,
					io.SeekStart,
				); err != nil {
					pw.CloseWithError(err)
					return
				}

				if _, err := io.CopyN(
					part,
					content,
					ra.length,
				); err != nil {
					pw.CloseWithError(err)
					return
				}
			}

			mw.Close()
			pw.Close()
		}()
	}

	canWrite = true

	return nil
}

// WriteBlob responds to the client with the content b.
func (r *Response) WriteBlob(b []byte) error {
	if ct := r.Headers["content-type"].Value(); ct != "" {
		var err error
		if b, err = theMinifier.minify(ct, b); err != nil {
			return err
		}
	}

	return r.Write(bytes.NewReader(b))
}

// WriteString responds to the client with the "text/plain" content s.
func (r *Response) WriteString(s string) error {
	r.SetHeader("content-type", "text/plain; charset=utf-8")
	return r.WriteBlob([]byte(s))
}

// WriteJSON responds to the client with the "application/json" content v.
func (r *Response) WriteJSON(v interface{}) error {
	var (
		b   []byte
		err error
	)

	if DebugMode {
		b, err = jsoniter.MarshalIndent(v, "", "\t")
	} else {
		b, err = jsoniter.Marshal(v)
	}

	if err != nil {
		return err
	}

	r.SetHeader("content-type", "application/json; charset=utf-8")
	return r.WriteBlob(b)
}

// WriteMsgPack responds to the client with the "application/msgpack" content v.
func (r *Response) WriteMsgPack(v interface{}) error {
	var (
		b   []byte
		err error
	)

	b, err = msgpack.Marshal(v)
	if err != nil {
		return err
	}

	r.SetHeader("content-type", "application/msgpack")
	return r.WriteBlob(b)
}

// WriteXML responds to the client with the "application/xml" content v.
func (r *Response) WriteXML(v interface{}) error {
	var (
		b   []byte
		err error
	)

	if DebugMode {
		b, err = xml.MarshalIndent(v, "", "\t")
	} else {
		b, err = xml.Marshal(v)
	}

	if err != nil {
		return err
	}

	b = append([]byte(xml.Header), b...)

	r.SetHeader("content-type", "application/xml; charset=utf-8")
	return r.WriteBlob(b)
}

// WriteHTML responds to the client with the "text/html" content h.
func (r *Response) WriteHTML(h string) error {
	if AutoPushEnabled && r.request.Request.ProtoMajor == 2 {
		tree, err := html.Parse(strings.NewReader(h))
		if err != nil {
			return err
		}

		var f func(*html.Node)
		f = func(n *html.Node) {
			if n.Type == html.ElementNode {
				target := ""
				switch n.Data {
				case "link":
					for _, a := range n.Attr {
						if a.Key == "href" {
							target = a.Val
							break
						}
					}
				case "img", "script":
					for _, a := range n.Attr {
						if a.Key == "src" {
							target = a.Val
							break
						}
					}
				}

				if path.IsAbs(target) {
					r.Push(target, nil)
				}
			}

			for c := n.FirstChild; c != nil; c = c.NextSibling {
				f(c)
			}
		}

		f(tree)
	}

	r.SetHeader("content-type", "text/html; charset=utf-8")
	return r.WriteBlob([]byte(h))
}

// Render renders one or more HTML templates with the m and responds to the
// client with the "text/html" content. The results rendered by the former can
// be inherited by accessing the `m["InheritedHTML"]`.
func (r *Response) Render(m map[string]interface{}, templates ...string) error {
	buf := bytes.Buffer{}
	for _, t := range templates {
		m["InheritedHTML"] = template.HTML(buf.String())
		buf.Reset()
		err := theRenderer.render(&buf, t, m)
		if err != nil {
			return err
		}
	}

	return r.WriteHTML(buf.String())
}

// WriteFile responds to the client with a file content with the filename.
func (r *Response) WriteFile(filename string) error {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return err
	} else if fi, err := os.Stat(filename); err != nil {
		return err
	} else if fi.IsDir() {
		if p := r.request.Request.URL.EscapedPath(); !hasLastSlash(p) {
			p = path.Base(p) + "/"
			if q := r.request.Request.URL.RawQuery; q != "" {
				p += "?" + q
			}

			r.Status = 301

			return r.Redirect(p)
		}

		filename += "index.html"
	}

	var (
		c  io.ReadSeeker
		ct string
		et []byte
		mt time.Time
	)
	if a, err := theCoffer.asset(filename); err != nil {
		return err
	} else if a != nil {
		if a.isCompressed && strings.Contains(r.request.Request.Header.Get("accept-encoding"), "gzip") {
			r.SetHeader("content-encoding", "gzip")
			r.SetHeader("vary", "accept-encoding")
			c = bytes.NewReader(a.compressed)
		} else {
			c = bytes.NewReader(a.content)
		}
		ct = a.mimeType
		et = a.checksum[:]
		mt = a.modTime
	} else {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			return err
		}

		c = f
		mt = fi.ModTime()
	}

	if r.Headers["content-type"].Value() == "" {
		if ct == "" {
			ct = mime.TypeByExtension(filepath.Ext(filename))
		}

		if ct == "" {
			// Read a chunk to decide between UTF-8 text and binary
			b := [1 << 9]byte{}
			n, _ := io.ReadFull(c, b[:])
			ct = http.DetectContentType(b[:n])
			if _, err := c.Seek(0, io.SeekStart); err != nil {
				return err
			}
		}

		r.SetHeader("content-type", ct)
	}

	if r.Headers["etag"].Value() == "" {
		if et == nil {
			h := sha256.New()
			if _, err := io.Copy(h, c); err != nil {
				return err
			}

			et = h.Sum(nil)
		}

		r.SetHeader("etag", fmt.Sprintf(`"%x"`, et))
	}

	if r.Headers["last-modified"].Value() == "" {
		r.SetHeader("last-modified", mt.UTC().Format(http.TimeFormat))
	}

	return r.Write(c)
}

// Redirect responds to the client with a redirection to the url.
func (r *Response) Redirect(url string) error {
	if r.Status < 300 || r.Status >= 400 {
		r.Status = 302
	}

	r.SetHeader("location", url)
	return r.Write(nil)
}

// WebSocket switches the connection to the WebSocket protocol.
func (r *Response) WebSocket() (*WebSocket, error) {
	r.Status = 101

	if len(r.Cookies) > 0 {
		vs := make([]string, 0, len(r.Cookies))
		for _, c := range r.Cookies {
			vs = append(vs, c.String())
		}

		r.SetHeaderValues("set-cookie", vs)
	}

	for n, h := range r.Headers {
		n := textproto.CanonicalMIMEHeaderKey(n)
		r.Writer.Header()[n] = h.Values
	}

	r.Written = true

	wsu := &websocket.Upgrader{
		HandshakeTimeout: WebSocketHandshakeTimeout,
		Error: func(
			_ http.ResponseWriter,
			_ *http.Request,
			status int,
			_ error,
		) {
			r.Status = status
			r.Written = false
		},
		CheckOrigin: func(*http.Request) bool {
			return true
		},
	}
	if len(WebSocketSubprotocols) > 0 {
		wsu.Subprotocols = WebSocketSubprotocols
	}

	conn, err := wsu.Upgrade(r.Writer, r.request.Request, r.Writer.Header())
	if err != nil {
		return nil, err
	}

	ws := &WebSocket{
		conn: conn,
	}

	conn.SetCloseHandler(func(statusCode int, reason string) error {
		if ws.ConnectionCloseHandler != nil {
			return ws.ConnectionCloseHandler(statusCode, reason)
		}

		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(statusCode, ""),
			time.Now().Add(time.Second),
		)

		return nil
	})

	conn.SetPingHandler(func(appData string) error {
		if ws.PingHandler != nil {
			return ws.PingHandler(appData)
		}

		err := conn.WriteControl(
			websocket.PongMessage,
			[]byte(appData),
			time.Now().Add(time.Second),
		)
		if err == websocket.ErrCloseSent {
			return nil
		} else if e, ok := err.(net.Error); ok && e.Temporary() {
			return nil
		}

		return err
	})

	conn.SetPongHandler(func(appData string) error {
		if ws.PongHandler != nil {
			return ws.PongHandler(appData)
		}

		return nil
	})

	go func() {
		for {
			if ws.closed {
				break
			} else if ws.TextHandler == nil &&
				ws.BinaryHandler == nil {
				time.Sleep(time.Millisecond)
				continue
			}

			mt, r, err := conn.NextReader()
			if err != nil {
				if ws.ErrorHandler != nil {
					ws.ErrorHandler(err)
				}

				break
			}

			switch mt {
			case websocket.TextMessage:
				if ws.TextHandler != nil {
					var b []byte
					b, err = ioutil.ReadAll(r)
					if err == nil {
						err = ws.TextHandler(string(b))
					}
				}
			case websocket.BinaryMessage:
				if ws.BinaryHandler != nil {
					var b []byte
					b, err = ioutil.ReadAll(r)
					if err == nil {
						err = ws.BinaryHandler(b)
					}
				}
			}

			if err != nil && ws.ErrorHandler != nil {
				ws.ErrorHandler(err)
			}
		}
	}()

	return ws, nil
}

// Push initiates an HTTP/2 server push. This constructs a synthetic request
// using the target and headers, serializes that request into a PUSH_PROMISE
// frame, then dispatches that request using the server's request handler. The
// target must either be an absolute path (like "/path") or an absolute URL
// that contains a valid host and the same scheme as the parent request. If the
// target is a path, it will inherit the scheme and host of the parent request.
// The headers specifies additional promised request headers. The headers
// cannot include HTTP/2 pseudo headers like ":path" and ":scheme", which
// will be added automatically.
func (r *Response) Push(target string, headers map[string]*Header) error {
	p, ok := r.Writer.(http.Pusher)
	if !ok {
		return nil
	}

	var pos *http.PushOptions
	if l := len(headers); l > 0 {
		pos = &http.PushOptions{
			Header: make(http.Header, l),
		}
		for n, h := range headers {
			n := textproto.CanonicalMIMEHeaderKey(n)
			pos.Header[n] = h.Values
		}
	}

	return p.Push(target, pos)
}

// scanETag determines if a syntactically valid ETag is present at s. If so, the
// ETag and remaining text after consuming ETag is returned. Otherwise, it
// returns "", "".
func scanETag(s string) (eTag string, remain string) {
	s = textproto.TrimString(s)
	start := 0
	if strings.HasPrefix(s, "W/") {
		start = 2
	}

	if len(s[start:]) < 2 || s[start] != '"' {
		return "", ""
	}

	// ETag is either W/"text" or "text".
	// See RFC 723, section 2.3.
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		// Character values allowed in ETags.
		case c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80:
		case c == '"':
			return string(s[:i+1]), s[i+1:]
		default:
			return "", ""
		}
	}

	return "", ""
}

// eTagStrongMatch reports whether the a and the b match using strong ETag
// comparison.
func eTagStrongMatch(a, b string) bool {
	return a == b && a != "" && a[0] == '"'
}

// eTagWeakMatch reports whether the a and the b match using weak ETag
// comparison.
func eTagWeakMatch(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// httpRange specifies the byte range to be sent to the client.
type httpRange struct {
	start, length int64
}

// contentRange return a Content-Range header of the r.
func (r httpRange) contentRange(size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.start, r.start+r.length-1, size)
}

// header return  the MIME header of the r.
func (r httpRange) header(contentType string, size int64) textproto.MIMEHeader {
	return textproto.MIMEHeader{
		"Content-Range": {r.contentRange(size)},
		"Content-Type":  {contentType},
	}
}

// countingWriter counts how many bytes have been written to it.
type countingWriter int64

// Write implements the `io.Writer`.
func (w *countingWriter) Write(p []byte) (int, error) {
	*w += countingWriter(len(p))
	return len(p), nil
}

// responseBody provides a convenient way to respond to the client with the
// streaming content.
type responseBody struct {
	response *Response
}

// Write implements the `io.Writer`.
func (rb *responseBody) Write(b []byte) (int, error) {
	if !rb.response.Written {
		rb.response.ContentLength = -1
		if err := rb.response.Write(nil); err != nil {
			return 0, err
		}
		rb.response.ContentLength = 0
	}
	n, err := rb.response.Writer.Write(b)
	rb.response.ContentLength += int64(n)
	return n, err
}
