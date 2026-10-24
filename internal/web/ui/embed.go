// Package ui embeds the built frontend (web/ → internal/web/ui/dist via `make ui`).
// Until the React build is available, a static placeholder shell is embedded.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the UI file system rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
