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
	Server *http.Server
	NonTLS *http.Server
}

// TheServer is the singleton of the `server`.
var TheServer = &server{
	Server: &http.Server{},
}

// serve starts the s.
func (s *server) serve() error {
	s.Server.Addr = Address
	s.Server.Handler = s
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

	if TLSCertFile != "" && TLSKeyFile != "" {
		host := s.Server.Addr
		if strings.Contains(host, ":") {
			var err error
			if host, _, err = net.SplitHostPort(host); err != nil {
				return err
			}
		}

		s.NonTLS = &http.Server{}

		var h2hs http.HandlerFunc
		h2hs = func(rw http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}

			http.Redirect(rw, r, "https://"+host+r.RequestURI, 301)
		}

		tlsCertFile, tlsKeyFile := TLSCertFile, TLSKeyFile
		if AutoCert && !(DevAutoCert && DebugMode) {
			acm := autocert.Manager{
				Prompt: autocert.AcceptTOS,
				Cache:  autocert.DirCache(ACMECertRoot),
			}
			if len(HostWhitelist) > 0 {
				acm.HostPolicy = autocert.HostWhitelist(
					HostWhitelist...,
				)
			}

			if MaintainerEmail != "" {
				acm.Email = MaintainerEmail
			}

			s.NonTLS.Handler = acm.HTTPHandler(h2hs)
			s.NonTLS.Addr = host + ":http"
			go s.NonTLS.ListenAndServe()

			s.Server.Addr = host + ":https"
			s.Server.TLSConfig = acm.TLSConfig()
			tlsCertFile, tlsKeyFile = "", ""
		} else if HTTPSEnforced {
			s.NonTLS.Handler = h2hs
			s.NonTLS.Addr = host + ":http"
			go s.NonTLS.ListenAndServe()
		}

		return s.Server.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
	}

	return s.Server.ListenAndServe()
}

// close closes the s immediately.
func (s *server) close() error {
	if s.NonTLS != nil {
		s.NonTLS.Close()
	}
	return s.Server.Close()
}

// shutdown gracefully shuts down the s without interrupting any active
// connections until timeout. It waits indefinitely for connections to return to
// idle and then shut down when the timeout is less than or equal to zero.
func (s *server) shutdown(timeout time.Duration) error {
	ctx := context.Background()
	if timeout <= 0 {
		if s.NonTLS != nil {
			s.NonTLS.Shutdown(ctx)
		}
		return s.Server.Shutdown(ctx)
	}

	c, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if s.NonTLS != nil {
		s.NonTLS.Shutdown(c)
	}
	return s.Server.Shutdown(c)
}

// ServeHTTP implements the `http.Handler`.
func (s *server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	// Check host

	if len(HostWhitelist) > 0 {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}

		allowed := false
		for _, h := range HostWhitelist {
			if h == host {
				allowed = true
				break
			}
		}

		if !allowed {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}

			http.Redirect(
				rw,
				r,
				scheme+"://"+HostWhitelist[0]+r.RequestURI,
				301,
			)

			return
		}
	}

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

		request:          r,
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
		writer:  rw,
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
