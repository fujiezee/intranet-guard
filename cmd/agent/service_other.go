//go:build !windows

package main

import "context"

const defaultStatePath = "/var/lib/safe-agent/state.json"

func runAsService(func(context.Context) error) (bool, error) { return false, nil }
