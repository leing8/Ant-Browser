//go:build !windows

package main

func checkProfileDirInUse(userDataDir string) (bool, string) {
	return false, ""
}

func listRunningAntBrowserProcesses() []string {
	return nil
}
