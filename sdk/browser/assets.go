// Package browser 提供与 TypeScript 源码一致的浏览器 SDK 静态产物。
package browser

import _ "embed"

//go:embed dist/index.js
var JavaScript []byte
