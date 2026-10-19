package password

import (
	"strings"
	"testing"
)

func TestPasswordStorage(t *testing.T) {
	const value = "local-test-password-strong"
	first, e := Hash(value)
	if e != nil {
		t.Fatal(e)
	}
	second, e := Hash(value)
	if e != nil || first == second {
		t.Fatal("随机盐未生效")
	}
	if !Verify(first, value) || Verify(first, value+"wrong") || Verify(strings.Replace(first, "600000", "1", 1), value) || Verify("", value) {
		t.Fatal("口令核验边界错误")
	}
	for _, value := range []string{"short", strings.Repeat("a", 1025), string([]byte{0xff})} {
		if _, e := Hash(value); e == nil {
			t.Fatal("无效口令被接收")
		}
	}
}
