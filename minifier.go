package air

import (
	"bytes"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"sync"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
	"github.com/tdewolff/minify/v2/json"
	"github.com/tdewolff/minify/v2/svg"
	"github.com/tdewolff/minify/v2/xml"
)

// minifier is a minifier that minifies contents based on the MIME types.
type minifier struct {
	minifier *minify.M
	once     *sync.Once
}

// theMinifier is the singleton of the `minifier`.
var theMinifier = &minifier{
	minifier: minify.New(),
	once:     &sync.Once{},
}

// minify minifies the b based on the mimeType.
func (m *minifier) minify(mimeType string, b []byte) ([]byte, error) {
	if !MinifierEnabled {
		return b, nil
	}

	m.once.Do(func() {
		m.minifier.Add("text/html", html.DefaultMinifier)
		m.minifier.Add("text/css", css.DefaultMinifier)
		m.minifier.Add("application/javascript", js.DefaultMinifier)
		m.minifier.Add("application/json", json.DefaultMinifier)
		m.minifier.Add("application/xml", xml.DefaultMinifier)
		m.minifier.Add("image/svg+xml", svg.DefaultMinifier)
		m.minifier.AddFunc("image/jpeg", func(
			m *minify.M,
			w io.Writer,
			r io.Reader,
			params map[string]string,
		) error {
			img, err := jpeg.Decode(r)
			if err != nil {
				return err
			}

			return jpeg.Encode(w, img, nil)
		})
		m.minifier.AddFunc("image/png", func(
			m *minify.M,
			w io.Writer,
			r io.Reader,
			params map[string]string,
		) error {
			img, err := png.Decode(r)
			if err != nil {
				return err
			}

			return (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(w, img)
		})
	})

	mimeType, _, err := mime.ParseMediaType(mimeType)
	if err != nil {
		return nil, err
	}

	buf := bytes.Buffer{}
	if err := m.minifier.Minify(
		mimeType,
		&buf,
		bytes.NewReader(b),
	); err == minify.ErrNotExist {
		return b, nil
	} else if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
