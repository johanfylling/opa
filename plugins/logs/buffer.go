// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logs

import (
	"container/list"
	"fmt"
)

// logBuffer implements a circular FIFO buffer for the plugin that caps memory
// usage at the configured limit. If the buffer size is exceeded, events from
// the front of the buffer are dropped.
type logBuffer struct {
	usage int64
	limit int64
	l     *list.List
}

type logBufferElem struct {
	bs []byte
}

func newLogBuffer(limit int64) *logBuffer {
	return &logBuffer{
		limit: limit,
		usage: 0,
		l:     list.New(),
	}
}

type TooLargeError struct {
	Limit int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("log buffer size limit exceeded (%d)", e.Limit)
}

func (lb *logBuffer) Push(bs []byte, allowDrop bool) (int, error) {
	size := int64(len(bs))
	dropped := 0

	if lb.limit > 0 {
		for elem := lb.l.Front(); elem != nil && (lb.usage+size > lb.limit); elem = elem.Next() {
			if !allowDrop {
				return 0, &TooLargeError{Limit: lb.limit}
			}

			drop := elem.Value.(logBufferElem).bs
			lb.l.Remove(elem)
			lb.usage -= int64(len(drop))
			dropped++
		}
	}

	elem := logBufferElem{bs}

	lb.l.PushBack(elem)
	lb.usage += size
	return dropped, nil
}

func (lb *logBuffer) Pop() []byte {
	elem := lb.l.Front()
	if elem != nil {
		e := elem.Value.(logBufferElem)
		lb.usage -= int64(len(e.bs))
		lb.l.Remove(elem)
		return e.bs
	}
	return nil
}

func (lb *logBuffer) Len() int {
	return lb.l.Len()
}
