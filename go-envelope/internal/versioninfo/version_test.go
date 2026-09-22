package versioninfo

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestCalendarStrictUTCAndDeclaredScheme(t *testing.T) {
	for _, value := range []string{"260922094507.0.0", "280229235959.0.0", "991231235959.0.0"} {
		if _, err := Calendar(value, Scheme); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{"0.1.44", "26.09.22", "260229120000.0.0", "260431120000.0.0", "260922240000.0.0", "260922126000.0.0", "260922125960.0.0", "090922120000.0.0", "260922094507.0.1", "260922094507.0.0-rc1", "260922094507.0.0+sha"} {
		if _, err := Calendar(value, Scheme); err == nil {
			t.Fatal("accepted", value)
		}
	}
	for _, scheme := range []string{"", "legacy", "inspr-calendar-v1", "unknown"} {
		if _, err := Calendar(Current.Version, scheme); err == nil {
			t.Fatal("accepted undeclared scheme")
		}
	}
}
func TestPresentationRejectsEveryClosureMutation(t *testing.T) {
	copyFS := func() fstest.MapFS {
		result := fstest.MapFS{}
		fs.WalkDir(assets, "presentation", func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() {
				raw, _ := assets.ReadFile(path)
				result[path] = &fstest.MapFile{Data: raw, Mode: 0644}
			}
			return nil
		})
		return result
	}
	if err := VerifyPresentation(copyFS()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(fstest.MapFS){
		"missing": func(f fstest.MapFS) { delete(f, "presentation/auto-animate-license.js") },
		"extra": func(f fstest.MapFS) {
			f["presentation/extra.js"] = &fstest.MapFile{Data: []byte("ignored?"), Mode: 0644}
		},
		"hidden":  func(f fstest.MapFS) { f["presentation/.hidden"] = &fstest.MapFile{Mode: 0644} },
		"changed": func(f fstest.MapFS) { f["presentation/version.js"].Data = []byte("changed") },
		"manifest": func(f fstest.MapFS) {
			f["presentation/manifest.json"].Data = append(f["presentation/manifest.json"].Data, ' ')
		},
		"symlink": func(f fstest.MapFS) { f["presentation/display.json"].Mode = fs.ModeSymlink | 0644 },
	} {
		t.Run(name, func(t *testing.T) {
			f := copyFS()
			mutate(f)
			if VerifyPresentation(f) == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}
