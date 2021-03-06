package air

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// server is an HTTP server.
type server struct {
	Server           *http.Server
	H2HSServer       *http.Server
	InterceptHandler func(http.Handler) http.Handler
}

// TheServer is the singleton of the `server`.
var TheServer = &server{
	Server: &http.Server{},
}

// serve starts the s.
func (s *server) serve() error {
	s.Server.Addr = Address
	if s.InterceptHandler != nil {
		s.Server.Handler = s.InterceptHandler(s)
	} else {
		s.Server.Handler = s
	}
	s.Server.ReadTimeout = ReadTimeout
	s.Server.ReadHeaderTimeout = ReadHeaderTimeout
	s.Server.WriteTimeout = WriteTimeout
	s.Server.IdleTimeout = IdleTimeout
	s.Server.MaxHeaderBytes = MaxHeaderBytes
	s.Server.ErrorLog = log.New(&serverErrorLogWriter{}, "air: ", 0)

	if DebugMode {
		LoggerLowestLevel = LoggerLevelDebug
		DEBUG("air: serving in debug mode")
	}

	if TLSCertFile == "" || TLSKeyFile == "" || !HTTPSEnforced {
		return s.Server.ListenAndServe()
	}

	host := s.Server.Addr
	if strings.Contains(host, ":") {
		var err error
		if host, _, err = net.SplitHostPort(host); err != nil {
			return err
		}
	}

	s.H2HSServer = &http.Server{}

	var h2hs http.HandlerFunc
	h2hs = func(res http.ResponseWriter, req *http.Request) {
		target := "https://" + req.Host + req.URL.Path
		if len(req.URL.RawQuery) > 0 {
			target += "?" + req.URL.RawQuery
		}
		http.Redirect(res, req, target, 301)
	}

	tlsCertFile, tlsKeyFile := TLSCertFile, TLSKeyFile
	if AutoCert && !(DebugMode && !DevAutoCert) {
		acm := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(ACMECertRoot),
			Email:  MaintainerEmail,
		}

		if len(HostWhitelist) > 0 {
			acm.HostPolicy = autocert.HostWhitelist(HostWhitelist...)
		}

		s.H2HSServer.Handler = acm.HTTPHandler(h2hs)
		s.H2HSServer.Addr = host + ":http"
		go s.H2HSServer.ListenAndServe()

		s.Server.Addr = host + ":https"
		s.Server.TLSConfig = acm.TLSConfig()
		tlsCertFile, tlsKeyFile = "", ""
	} else {
		s.H2HSServer.Handler = h2hs
		s.H2HSServer.Addr = host + ":http"
		go s.H2HSServer.ListenAndServe()
	}

	return s.Server.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
}

// close closes the s immediately.
func (s *server) close() error {
	if s.H2HSServer != nil {
		s.H2HSServer.Close()
	}
	return s.Server.Close()
}

// shutdown gracefully shuts down the s without interrupting any active
// connections until timeout. It waits indefinitely for connections to return to
// idle and then shut down when the timeout is less than or equal to zero.
func (s *server) shutdown(timeout time.Duration) error {
	ctx := context.Background()
	if timeout <= 0 {
		if s.H2HSServer != nil {
			s.H2HSServer.Shutdown(ctx)
		}
		return s.Server.Shutdown(ctx)
	}

	c, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if s.H2HSServer != nil {
		s.H2HSServer.Shutdown(c)
	}
	return s.Server.Shutdown(c)
}

// ServeHTTP implements the `http.Handler`.
func (s *server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	// Request

	req := &Request{
		Method:        r.Method,
		Scheme:        "http",
		Authority:     r.Host,
		Path:          r.RequestURI,
		Headers:       make(map[string]*Header, len(r.Header)),
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Cookies:       map[string]*Cookie{},
		Params: make(
			map[string]*RequestParam,
			theRouter.maxParams,
		),
		RemoteAddress: r.RemoteAddr,
		ClientAddress: r.RemoteAddr,
		Values:        obj{},

		Request:          r,
		parseCookiesOnce: &sync.Once{},
		parseParamsOnce:  &sync.Once{},
	}

	if r.TLS != nil {
		req.Scheme = "https"
	}

	for n, vs := range r.Header {
		h := &Header{
			Name:   strings.ToLower(n),
			Values: vs,
		}
		req.Headers[h.Name] = h
	}

	if f := req.Headers["forwarded"].Value(); f != "" { // See RFC 7239
		for _, p := range strings.Split(strings.Split(f, ",")[0], ";") {
			p := strings.TrimSpace(p)
			if strings.HasPrefix(p, "for=") {
				req.ClientAddress = strings.TrimSuffix(
					strings.TrimPrefix(p[4:], "\"["),
					"]\"",
				)
				break
			}
		}
	} else if xff := req.Headers["x-forwarded-for"].Value(); xff != "" {
		req.ClientAddress = strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	// Response

	res := &Response{
		Status:  200,
		Headers: map[string]*Header{},
		Cookies: map[string]*Cookie{},

		request: req,
		Writer:  rw,
	}
	res.Body = &responseBody{
		response: res,
	}

	// Chain gases

	h := func(req *Request, res *Response) error {
		rh := theRouter.route(req)
		h := func(req *Request, res *Response) error {
			if err := rh(req, res); err != nil {
				return err
			} else if !res.Written {
				return res.Write(nil)
			}

			return nil
		}

		req.ParseCookies()
		req.ParseParams()

		for i := len(Gases) - 1; i >= 0; i-- {
			h = Gases[i](h)
		}

		return h(req, res)
	}

	// Chain pregases

	for i := len(Pregases) - 1; i >= 0; i-- {
		h = Pregases[i](h)
	}

	// Execute chain

	if err := h(req, res); err != nil {
		ErrorHandler(err, req, res)
	}

	// Close opened request param file values

	for _, p := range req.Params {
		for _, pv := range p.Values {
			if pv.f != nil && pv.f.f != nil {
				pv.f.f.Close()
			}
		}
	}
}

// serverErrorLogWriter is an HTTP server error log writer.
type serverErrorLogWriter struct{}

// Write implements the `io.Writer`.
func (selw *serverErrorLogWriter) Write(b []byte) (int, error) {
	ERROR(string(b))
	return len(b), nil
}
