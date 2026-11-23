// Package logfile writes Tender's JSON lines to its log directory, keeping
// one older file beside the current one.
package logfile

import (
	"os"
	"path/filepath"
	"sync"
)

// FileName is the log file's name.
const FileName = "tender.log"

// MaxSize is how large the log grows before it moves aside.
const MaxSize = 10 << 20

// Writer appends to dir/tender.log and moves it to tender.log.1 when it
// passes MaxSize.
type Writer struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// Open opens the log in dir, making dir when it is missing.
func Open(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &Writer{path: filepath.Join(dir, FileName)}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > MaxSize {
		w.f.Close()
		_ = os.Rename(w.path, w.path+".1")
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// Close closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
