// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
	"golang.org/x/sys/windows"
)

const (
	ML_SYSTEM_RID = 0x4000
)

// RunningUnderSupervisor returns true when executing Agent is running under
// the supervisor processes of the OS.
func RunningUnderSupervisor() bool {
	f, _ := os.OpenFile(filepath.Join(paths.Top(), "running.under.supervisor"), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	fmt.Fprintln(f, ">>> started")
	defer func() {
		fmt.Fprintln(f, "<<< stopped")
		f.Close()
	}()

	serviceSid, err := allocSid(ML_SYSTEM_RID)
	fmt.Fprintln(f, "allocsid", serviceSid, err)
	if err != nil {
		fmt.Fprintln(f, "allocSid return false")
		return false
	}
	defer windows.FreeSid(serviceSid)

	t, err := windows.OpenCurrentProcessToken()
	fmt.Fprintln(f, "OpenCurrentProcessToken", t, err)
	if err != nil {
		fmt.Fprintln(f, "OpenCurrentProcessToken return false")
		return false
	}
	defer t.Close()

	gs, err := t.GetTokenGroups()
	fmt.Fprintln(f, "GetTokenGroups", gs, err)
	if err != nil {
		fmt.Fprintln(f, "GetTokenGroups return false")
		return false
	}

	for _, g := range gs.AllGroups() {
		fmt.Fprintln(f, "checking group", g.Sid, serviceSid)
		if windows.EqualSid(g.Sid, serviceSid) {
			fmt.Fprintln(f, "EqualSid returns true")
			return true
		}
	}
	fmt.Fprintln(f, "everything failed")
	return false
}

func allocSid(subAuth0 uint32) (*windows.SID, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_MANDATORY_LABEL_AUTHORITY,
		1, subAuth0, 0, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return nil, err
	}
	return sid, nil
}
