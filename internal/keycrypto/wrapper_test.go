package keycrypto

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func setup(t *testing.T) (*Wrapper, Binding, []byte) {
	t.Helper()
	root, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	w, err := New("root-v1", root)
	if err != nil {
		t.Fatal(err)
	}
	key, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return w, Binding{"test", "client-1", "key-1", 1, "authentication"}, key
}
func TestRoundTripAndNonce(t *testing.T) {
	w, b, key := setup(t)
	a, err := w.Seal(b, key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := w.Seal(b, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Ciphertext, other.Ciphertext) {
		t.Fatal("nonce reused")
	}
	got, err := w.Open(b, a)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("round trip failed", err)
	}
	got[0] ^= 1
	got, err = w.Open(b, a)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("output alias")
	}
}
func TestTamperingAndScope(t *testing.T) {
	w, b, key := setup(t)
	e, _ := w.Seal(b, key)
	mutations := []Binding{b, b, b, b, b}
	mutations[0].Environment = "other"
	mutations[1].ClientID = "other"
	mutations[2].KeyID = "other"
	mutations[3].Version++
	mutations[4].Purpose = "other"
	for _, wrong := range mutations {
		if got, err := w.Open(wrong, e); !errors.Is(err, ErrOpen) || got != nil {
			t.Fatal("scope substitution accepted")
		}
	}
	for i := range e.Ciphertext {
		copyE := e
		copyE.Ciphertext = bytes.Clone(e.Ciphertext)
		copyE.Ciphertext[i] ^= 1
		if got, err := w.Open(b, copyE); !errors.Is(err, ErrOpen) || got != nil {
			t.Fatal("tampering accepted")
		}
	}
	wrongFormat := e
	wrongFormat.Format = "unknown"
	if _, err := w.Open(b, wrongFormat); !errors.Is(err, ErrOpen) {
		t.Fatal(err)
	}
	wrongRoot := e
	wrongRoot.RootID = "root-v2"
	if _, err := w.Open(b, wrongRoot); !errors.Is(err, ErrOpen) {
		t.Fatal(err)
	}
	root, _ := Generate()
	other, _ := New("root-v1", root)
	if _, err := other.Open(b, e); !errors.Is(err, ErrOpen) {
		t.Fatal("wrong key accepted")
	}
}
func TestInvalidInputs(t *testing.T) {
	w, b, key := setup(t)
	if _, err := New("root", key[:16]); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := w.Seal(Binding{}, key); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := w.Seal(b, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	var nilWrapper *Wrapper
	if _, err := nilWrapper.Open(b, Envelope{}); !errors.Is(err, ErrOpen) {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, 27, 59, 61, 1024} {
		if _, err := w.Open(b, Envelope{Format, "root-v1", make([]byte, size)}); !errors.Is(err, ErrOpen) {
			t.Fatal(size, err)
		}
	}
}
func TestConcurrentWrapping(t *testing.T) {
	w, b, key := setup(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := w.Seal(b, key)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := w.Open(b, e)
			if err != nil || !bytes.Equal(got, key) {
				t.Error("concurrent wrap failed")
			}
		}()
	}
	wg.Wait()
}
