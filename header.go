package air

// Header is an HTTP header.
type Header struct {
	Name   string
	Values []string
}

// Value returns the first value of the h. It returns "" if the h is nil or
// there are no values.
func (h *Header) Value() string {
	if h == nil || len(h.Values) == 0 {
		return ""
	}

	return h.Values[0]
}

// Set easier way to set the header's value(s)
func (h *Header) Set(values ...string) {
	h.Values = values
}

// GenHeader makes a new header from a name and some values
func GenHeader(name string, values ...string) *Header {
	return &Header{Name: name, Values: values}
}
