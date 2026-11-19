//go:build !windows && !darwin

// process_check_other.go 为其他平台提供进程与文件占用检查的占位实现。
package main

// checkProfileDirInUse 在未适配平台默认返回未占用。
func checkProfileDirInUse(_ string) (bool, string) {
	return false, ""
}

// listRunningAntBrowserProcesses 在未适配平台返回空列表。
func listRunningAntBrowserProcesses() []string {
	return nil
}
