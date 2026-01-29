//go:build !darwin && !linux

package sai

func CheckPermissions() error {
	return nil
}

func wrapPermissionError(_ error) error {
	return nil
}
