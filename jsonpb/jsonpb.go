package jsonpb

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/golang/protobuf/proto"
	"io"

	// The OpenBazaar fork of this package better handles large integers. Normally
	// the package will marshal everything over 32 bits as a string. Whereas this
	// fork allows integers up to the maximum int handled by javascript of 53 bits.
	// It also emits enum 0 whereas the original package does not.
	"github.com/OpenBazaar/jsonpb"
)

// Marshaler is a configurable object for converting between
// protocol buffer objects and a JSON representation for them.
//
// The original jsonpb marshaler will marshal bytes as base64
// strings. For Bitcoin we obviously prefer hex strings. This
// marshaler will also convert all 32 byte litte endian arrays
// to big endian hex strings.
type Marshaler struct {
	// Whether to render enum values as integers, as opposed to string values.
	EnumsAsInts bool

	// Whether to render fields with zero values.
	EmitDefaults bool

	// A string to indent each level by. The presence of this field will
	// also cause a space to appear between the field separator and
	// value, and for newlines to be appear between fields and array
	// elements.
	Indent string

	// Whether to use the original (.proto) name for fields.
	OrigName bool
}

// Marshal marshals a protocol buffer into JSON.
func (m *Marshaler) Marshal(out io.Writer, pb proto.Message) error {
	marshaler := jsonpb.Marshaler{
		EnumsAsInts:  m.EnumsAsInts,
		EmitDefaults: m.EmitDefaults,
		Indent:       m.Indent,
		OrigName:     m.OrigName,
	}

	s, err := marshaler.MarshalToString(pb)
	if err != nil {
		return err
	}

	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return err
	}

	convertBase64(v)

	r, err := json.MarshalIndent(v, "", m.Indent)
	if err != nil {
		return err
	}
	_, err = out.Write(r)
	return err
}

// MarshalToString converts a protocol buffer object to JSON string.
func (m *Marshaler) MarshalToString(pb proto.Message) (string, error) {
	marshaler := jsonpb.Marshaler{
		EnumsAsInts:  m.EnumsAsInts,
		EmitDefaults: m.EmitDefaults,
		Indent:       m.Indent,
		OrigName:     m.OrigName,
	}

	s, err := marshaler.MarshalToString(pb)
	if err != nil {
		return "", err
	}

	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", err
	}

	convertBase64(v)

	out, err := json.MarshalIndent(v, "", m.Indent)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Unmarshaler is a configurable object for converting from a JSON
// representation to a protocol buffer object.
type Unmarshaler struct {
	// Whether to allow messages to contain unknown fields, as opposed to
	// failing to unmarshal.
	AllowUnknownFields bool
}

// UnmarshalNext unmarshals the next protocol buffer from a JSON object stream.
// This function is lenient and will decode any options permutations of the
// related Marshaler.
func (u *Unmarshaler) UnmarshalNext(dec *json.Decoder, pb proto.Message) error {

	var i interface{}
	if err := dec.Decode(&i); err != nil {
		return err
	}

	convertHex(i)

	out, err := json.Marshal(&i)
	if err != nil {
		return err
	}

	newDec := json.NewDecoder(bytes.NewReader(out))

	unMarshaler := jsonpb.Unmarshaler{
		AllowUnknownFields: u.AllowUnknownFields,
	}

	return unMarshaler.UnmarshalNext(newDec, pb)
}

// Unmarshal unmarshals a JSON object stream into a protocol
// buffer. This function is lenient and will decode any options
// permutations of the related Marshaler.
func (u *Unmarshaler) Unmarshal(r io.Reader, pb proto.Message) error {
	dec := json.NewDecoder(r)
	return u.UnmarshalNext(dec, pb)
}

// UnmarshalNext unmarshals the next protocol buffer from a JSON object stream.
// This function is lenient and will decode any options permutations of the
// related Marshaler.
func UnmarshalNext(dec *json.Decoder, pb proto.Message) error {
	return new(Unmarshaler).UnmarshalNext(dec, pb)
}

// Unmarshal unmarshals a JSON object stream into a protocol
// buffer. This function is lenient and will decode any options
// permutations of the related Marshaler.
func Unmarshal(r io.Reader, pb proto.Message) error {
	u := &Unmarshaler{true}
	return u.Unmarshal(r, pb)
}

func convertBase64(data interface{}) {
	switch d := data.(type) {
	case map[string]interface{}:
		for k, v := range d {
			switch tv := v.(type) {
			case string:
				decoded, err := base64.StdEncoding.DecodeString(tv)
				if err == nil && len(decoded) == 32 {
					ch, err := chainhash.NewHash(decoded)
					if err == nil {
						d[k] = ch.String()
					}
				} else if err == nil {
					d[k] = hex.EncodeToString(decoded)
				}
			case map[string]interface{}:
				convertBase64(tv)
			case []interface{}:
				convertBase64(tv)
			case nil:
				delete(d, k)
			}
		}
	case []interface{}:
		if len(d) > 0 {
			switch d[0].(type) {
			case string:
				for i, s := range d {
					decoded, err := base64.StdEncoding.DecodeString(s.(string))
					if err == nil && len(decoded) == 32 {
						ch, err := chainhash.NewHash(decoded)
						if err == nil {
							d[i] = ch.String()
						}
					} else if err == nil {
						d[i] = hex.EncodeToString(decoded)
					}
				}
			case map[string]interface{}:
				for _, t := range d {
					convertBase64(t)
				}
			case []interface{}:
				for _, t := range d {
					convertBase64(t)
				}
			}
		}
	}
}

func convertHex(data interface{}) {
	switch d := data.(type) {
	case map[string]interface{}:
		for k, v := range d {
			switch tv := v.(type) {
			case string:
				ch, err := chainhash.NewHashFromStr(tv)
				if err == nil && len(tv) == 64 {
					d[k] = base64.StdEncoding.EncodeToString(ch.CloneBytes())
					continue
				}
				decoded, err := hex.DecodeString(tv)
				if err == nil {
					d[k] = base64.StdEncoding.EncodeToString(decoded)
				}
			case map[string]interface{}:
				convertHex(tv)
			case []interface{}:
				convertHex(tv)
			case nil:
				delete(d, k)
			}
		}
	case []interface{}:
		if len(d) > 0 {
			switch d[0].(type) {
			case string:
				for i, s := range d {
					ch, err := chainhash.NewHashFromStr(s.(string))
					if err == nil && len(s.(string)) == 64 {
						d[i] = base64.StdEncoding.EncodeToString(ch.CloneBytes())
						continue
					}
					decoded, err := hex.DecodeString(s.(string))
					if err == nil {
						d[i] = base64.StdEncoding.EncodeToString(decoded)
					}
				}
			case map[string]interface{}:
				for _, t := range d {
					convertHex(t)
				}
			case []interface{}:
				for _, t := range d {
					convertHex(t)
				}
			}
		}
	}
}
