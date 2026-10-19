// Package manifest 为服务端生成的固定 schema 清单提供受限 JCS 编码。
// 不接受外部任意 JSON，不支持浮点数；字段名只允许 ASCII，业务版本使用字符串。
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf8"
)

var ErrInvalid = errors.New("unsupported canonical manifest")

func Canonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	if !validStrings(reflect.ValueOf(v)) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if e = d.Decode(&value); e != nil {
		return nil, e
	}
	return appendValue(nil, value)
}
func appendString(dst []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, ErrInvalid
	}
	dst = append(dst, '"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			dst = append(dst, '\\', byte(r))
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\r':
			dst = append(dst, '\\', 'r')
		default:
			if r < 32 {
				const h = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', h[byte(r)>>4], h[byte(r)&15])
			} else {
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return append(dst, '"'), nil
}
func appendValue(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		return strconv.AppendBool(dst, x), nil
	case string:
		return appendString(dst, x)
	case json.Number:
		n, e := strconv.ParseInt(string(x), 10, 64)
		if e != nil || n > 9007199254740991 || n < -9007199254740991 {
			return nil, ErrInvalid
		}
		return strconv.AppendInt(dst, n, 10), nil
	case []any:
		dst = append(dst, '[')
		for i, item := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var e error
			dst, e = appendValue(dst, item)
			if e != nil {
				return nil, e
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			for _, r := range key {
				if r < 32 || r > 126 {
					return nil, ErrInvalid
				}
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		dst = append(dst, '{')
		for i, key := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst, _ = appendString(dst, key)
			dst = append(dst, ':')
			var e error
			dst, e = appendValue(dst, x[key])
			if e != nil {
				return nil, e
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, ErrInvalid
	}
}

// encoding/json 会替换非法 UTF-8；必须在编码前拒绝，避免不同输入被归并为同一批准内容。
func validStrings(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.String:
		return utf8.ValidString(v.String())
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return true
		}
		return validStrings(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath == "" && !validStrings(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !validStrings(v.Index(i)) {
				return false
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if !validStrings(iter.Key()) || !validStrings(iter.Value()) {
				return false
			}
		}
	}
	return true
}
