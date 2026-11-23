//go:build !windows && !(darwin && cgo)

package identity

import (
	"errors"
	"time"
)

// HasStore says this operating system has no store Tender uses: it reads a
// key file and a cert file.
const HasStore = false

func loadStore(string, time.Time) (*Identity, error) {
	return nil, errors.New("this build has no certificate store; name identity.key and identity.cert")
}

func osStore() (Store, error) {
	return nil, errors.New("this build has no certificate store")
}
