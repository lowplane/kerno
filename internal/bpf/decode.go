// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func DecodeSyscallEvent(data []byte) (*SyscallEvent, error) {
	var event SyscallEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding syscall event: %w", err)
	}
	return &event, nil
}

func DecodeTCPEvent(data []byte) (*TCPEvent, error) {
	var event TCPEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding tcp event: %w", err)
	}
	return &event, nil
}

func DecodeOOMEvent(data []byte) (*OOMEvent, error) {
	var event OOMEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding oom event: %w", err)
	}
	return &event, nil
}

func DecodeDiskEvent(data []byte) (*DiskEvent, error) {
	var event DiskEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding disk event: %w", err)
	}
	return &event, nil
}

func DecodeSchedEvent(data []byte) (*SchedEvent, error) {
	var event SchedEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding sched event: %w", err)
	}
	return &event, nil
}

func DecodeFDEvent(data []byte) (*FDEvent, error) {
	var event FDEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding fd event: %w", err)
	}
	return &event, nil
}
