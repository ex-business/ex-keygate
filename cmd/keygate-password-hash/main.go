// 口令通过标准输入读入；禁止命令行参数，避免口令进入进程列表。
package main

import (
	"ex-keygate/internal/password"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 1026))
	if e != nil || len(raw) > 1025 {
		fmt.Fprintln(os.Stderr, "口令输入无效")
		os.Exit(1)
	}
	value := strings.TrimSuffix(string(raw), "\n")
	clear(raw)
	encoded, e := password.Hash(value)
	if e != nil {
		fmt.Fprintln(os.Stderr, "口令至少12个字符，最多1024字节")
		os.Exit(1)
	}
	fmt.Println(encoded)
}
