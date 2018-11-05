package air

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	// Compressable - list of compressable file types, append to it if needed
	Compressable = []string{"", ".txt", ".htm", ".html", ".css", ".toml", ".php", ".js", ".json", ".md", ".mdown", ".xml", ".svg", ".go", ".cgi", ".py", ".pl", ".aspx", ".asp"}
)

// coffer is a binary asset file manager that uses runtime memory to reduce disk
// I/O pressure.
type coffer struct {
	assets  map[string]*asset
	watcher *fsnotify.Watcher
}

// theCoffer is the singleton of the `coffer`.
var theCoffer = &coffer{
	assets: map[string]*asset{},
}

func init() {
	var err error
	if theCoffer.watcher, err = fsnotify.NewWatcher(); err != nil {
		panic(fmt.Errorf(
			"air: failed to build coffer watcher: %v",
			err,
		))
	}

	go func() {
		for {
			select {
			case e := <-theCoffer.watcher.Events:
				if CofferEnabled {
					DEBUG(
						"air: asset file event occurs",
						obj{"file": e.Name, "event": e.Op.String()},
					)
				}

				delete(theCoffer.assets, e.Name)
			case err := <-theCoffer.watcher.Errors:
				if CofferEnabled {
					ERROR(
						"air: coffer watcher error",
						obj{"error": err.Error()},
					)
				}
			}
		}
	}()
}

// asset returns an `asset` from the c for the name.
func (c *coffer) asset(name string) (*asset, error) {
	if !CofferEnabled {
		return nil, nil
	}

	if a, ok := c.assets[name]; ok {
		return a, nil
	}
	ar, err := filepath.Abs(AssetRoot)
	if err != nil || !strings.HasPrefix(name, ar) {
		return nil, err
	}

	ext := filepath.Ext(name)
	if stringsContainsCI(AssetExts, ext) {
		return nil, nil
	}

	fi, err := os.Stat(name)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	mt := mime.TypeByExtension(ext)
	if mt != "" {
		if b, err = theMinifier.minify(mt, b); err != nil {
			return nil, err
		}
	}

	if err := c.watcher.Add(name); err != nil {
		return nil, err
	}

	c.assets[name] = &asset{
		name:     name,
		mimeType: mt,
		content:  b,
		checksum: sha256.Sum256(b),
		modTime:  fi.ModTime(),
	}

	for _, cext := range Compressable {
		if ext == cext {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			if _, err := gz.Write(b); err == nil {
				gz.Flush()
			}
			gz.Close()
			c.assets[name].compressed = buf.Bytes()
			c.assets[name].isCompressed = true
			break
		}
	}

	return c.assets[name], nil
}

// asset is a binary asset file.
type asset struct {
	name         string
	content      []byte
	compressed   []byte
	isCompressed bool
	mimeType     string
	checksum     [sha256.Size]byte
	modTime      time.Time
}

// stringsContainsCI reports whether a []string contains a particular string
// regardless of it being uppercase, lowercase or mixed.
func stringsContainsCI(list []string, match string) bool {
	match = strings.ToLower(match)
	for _, str := range list {
		if strings.ToLower(str) == match {
			return true
		}
	}

	return false
}
