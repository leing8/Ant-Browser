//go:build !windows

package main

type platformCandidate struct {
	path  string
	label string
}

func discoverPlatformReleaseCandidates() []platformCandidate {
	return nil
}
