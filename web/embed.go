// Package web contiene la interfaz estática del portal (embebida en el binario).
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

func Static() fs.FS {
	sub, _ := fs.Sub(files, "static")
	return sub
}
