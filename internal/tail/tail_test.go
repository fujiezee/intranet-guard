package tail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	os.WriteFile(path, []byte("old history\n"), 0o644)
	appendStr := func(s string) {
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		f.WriteString(s)
		f.Close()
	}
	read := func(st *State) ([]string, *State) {
		t.Helper()
		lines, next, err := ReadLines(path, st)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, l := range lines {
			out = append(out, string(l))
		}
		return out, next
	}

	lines, st := read(nil)
	if len(lines) != 0 {
		t.Fatalf("first read should skip history, got %v", lines)
	}

	appendStr("a\nb\npartial")
	lines, st = read(st)
	if len(lines) != 2 || lines[0] != "a" || lines[1] != "b" {
		t.Fatalf("got %v", lines)
	}

	appendStr(" line\n")
	lines, st = read(st)
	if len(lines) != 1 || lines[0] != "partial line" {
		t.Fatalf("partial line: got %v", lines)
	}

	// 轮转：旧文件被移走，新文件从头读。
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("rotated\n"), 0o644)
	lines, _ = read(st)
	if len(lines) != 1 || lines[0] != "rotated" {
		t.Fatalf("after rotation: got %v", lines)
	}
}
