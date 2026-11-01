//go:build windows

package agent

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 通过 wevtapi.dll 读取事件日志，渲染为 XML（UTF-16，与系统语言、代码页无关）后交给 ParseWinEvents。

var (
	modwevtapi            = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery          = modwevtapi.NewProc("EvtQuery")
	procEvtNext           = modwevtapi.NewProc("EvtNext")
	procEvtRender         = modwevtapi.NewProc("EvtRender")
	procEvtClose          = modwevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = modwevtapi.NewProc("EvtCreateBookmark")
	procEvtSeek           = modwevtapi.NewProc("EvtSeek")
)

const (
	evtQueryChannelPath        = 0x1
	evtQueryForwardDirection   = 0x100
	evtQueryReverseDirection   = 0x200
	evtRenderEventXML          = 1
	evtSeekRelativeToBookmark  = 4
	errNoMoreItems             = syscall.Errno(259)
	errInsufficientBuffer      = syscall.Errno(122)
	evtNextTimeoutMilliseconds = 2000
)

func init() {
	winlogQuery = queryWinlog
	winlogLatest = latestWinlogRecord
}

func evtQuery(channel, query string, flags uint32) (uintptr, error) {
	c, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	h, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(q)), uintptr(flags|evtQueryChannelPath))
	if h == 0 {
		return 0, fmt.Errorf("EvtQuery %s: %w", channel, e)
	}
	return h, nil
}

func evtClose(h uintptr) { procEvtClose.Call(h) }

func evtRender(h uintptr, buf *[]uint16) (string, error) {
	for {
		var used, props uint32
		var p uintptr
		if len(*buf) > 0 {
			p = uintptr(unsafe.Pointer(&(*buf)[0]))
		}
		r, _, e := procEvtRender.Call(0, h, evtRenderEventXML, uintptr(len(*buf)*2), p,
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString((*buf)[:used/2]), nil
		}
		if e == errInsufficientBuffer {
			*buf = make([]uint16, used/2+1)
			continue
		}
		return "", fmt.Errorf("EvtRender: %w", e)
	}
}

// evtFetch 从结果集中读取最多 max 条事件。
func evtFetch(rs uintptr, max int) ([]WinEvent, error) {
	handles := make([]uintptr, 100)
	buf := make([]uint16, 16384)
	var out []WinEvent
	var xmlb strings.Builder
	for len(out) < max {
		want := len(handles)
		if max-len(out) < want {
			want = max - len(out)
		}
		var n uint32
		r, _, e := procEvtNext.Call(rs, uintptr(want), uintptr(unsafe.Pointer(&handles[0])),
			evtNextTimeoutMilliseconds, 0, uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			if e == errNoMoreItems {
				break
			}
			return out, fmt.Errorf("EvtNext: %w", e)
		}
		xmlb.Reset()
		var renderErr error
		for i := 0; i < int(n); i++ {
			if renderErr == nil {
				s, err := evtRender(handles[i], &buf)
				if err != nil {
					renderErr = err
				}
				xmlb.WriteString(s)
			}
			evtClose(handles[i])
		}
		if renderErr != nil {
			return out, renderErr
		}
		evs, err := ParseWinEvents(strings.NewReader(xmlb.String()))
		if err != nil {
			return out, err
		}
		out = append(out, evs...)
	}
	return out, nil
}

// queryWinlog 返回 EventRecordID 大于 after 的事件。优先用书签直接定位，避免每次从日志开头扫描；
// 定位失败（记录已被覆盖或日志被清除）时退回按记录号过滤的查询。
func queryWinlog(channel string, after uint64, max int) ([]WinEvent, error) {
	rs, err := evtQuery(channel, "*", evtQueryForwardDirection)
	if err != nil {
		return nil, err
	}
	if !seekAfter(rs, channel, after) {
		evtClose(rs)
		if rs, err = evtQuery(channel, fmt.Sprintf("*[System[(EventRecordID>%d)]]", after), evtQueryForwardDirection); err != nil {
			return nil, err
		}
	}
	defer evtClose(rs)
	evs, err := evtFetch(rs, max)
	kept := evs[:0]
	for _, ev := range evs {
		if ev.RecordID > after { // 书签定位在 after 本身
			kept = append(kept, ev)
		}
	}
	return kept, err
}

func seekAfter(rs uintptr, channel string, after uint64) bool {
	xml := fmt.Sprintf(`<BookmarkList><Bookmark Channel='%s' RecordId='%d' IsCurrent='true'/></BookmarkList>`, channel, after)
	p, err := windows.UTF16PtrFromString(xml)
	if err != nil {
		return false
	}
	bm, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if bm == 0 {
		return false
	}
	defer evtClose(bm)
	r, _, _ := procEvtSeek.Call(rs, 0, bm, 0, evtSeekRelativeToBookmark)
	return r != 0
}

// latestWinlogRecord 返回日志中最新一条记录的编号（日志为空时为 0）。
func latestWinlogRecord(channel string) (uint64, error) {
	rs, err := evtQuery(channel, "*", evtQueryReverseDirection)
	if err != nil {
		return 0, err
	}
	defer evtClose(rs)
	evs, err := evtFetch(rs, 1)
	if err != nil || len(evs) == 0 {
		return 0, err
	}
	return evs[0].RecordID, nil
}
