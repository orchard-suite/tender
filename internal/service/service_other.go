//go:build !darwin && !linux && !windows

package service

import "errors"

var errUnsupported = errors.New("tender install knows no service manager on this operating system; run `tender run` at sign-in")

func Install(Spec) (string, error) { return "", errUnsupported }

func Uninstall() (string, error) { return "", errUnsupported }
