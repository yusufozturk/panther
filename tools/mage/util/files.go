package util

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	NpmDir   = "node_modules"
	SetupDir = ".setup"
)

var (
	PyEnv     = filepath.Join(SetupDir, "venv")
	GoLinter  = filepath.Join(SetupDir, "golangci-lint")
	Swagger   = filepath.Join(SetupDir, "swagger")
	Terraform = filepath.Join(SetupDir, "terraform")

	PyTargets = []string{
		"internal/compliance/remediation_aws",
		"internal/compliance/policy_engine",
		"internal/log_analysis/rules_engine",
	}
)

// Path to a node binary
func NodePath(binary string) string {
	return filepath.Join(NpmDir, ".bin", binary)
}

// Path to a pip binary
func PipPath(lib string) string {
	return filepath.Join(PyEnv, "bin", lib)
}

// Wrapper around filepath.Walk, logging errors as fatal.
func MustWalk(root string, handler func(string, os.FileInfo) error) {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("stat %s: %v", path, err)
		}
		return handler(path, info)
	})
	if err != nil {
		panic(fmt.Errorf("couldn't traverse %s: %v", root, err))
	}
}

// Wrapper around ioutil.ReadFile, logging errors as fatal.
func MustReadFile(path string) []byte {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("failed to read %s: %v", path, err))
	}
	return contents
}

// Wrapper around ioutil.WriteFile, creating the parent dirs if needed and logging errors as fatal.
func MustWriteFile(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		panic(fmt.Errorf("failed to create directory %s: %v", filepath.Dir(path), err))
	}

	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		panic(fmt.Errorf("failed to write file %s: %v", path, err))
	}
}
