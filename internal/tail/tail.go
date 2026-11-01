// Package tail 增量读取持续追加的日志文件，记录读取位置并处理日志轮转。
package tail

import (
	"bytes"
	"io"
	"os"
)

// MaxReadPerCycle 限制每次读取的数据量，日志暴涨时分多次追上。
const MaxReadPerCycle = 4 << 20

// State 记录读取位置；inode 变化或文件变小说明发生了轮转。
type State struct {
	Path   string `json:"path"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// ReadLines 从上次位置继续读取完整的行，返回新的读取位置。
// 首次读取（state 为空或路径变了）直接跳到文件末尾，不处理历史内容。
func ReadLines(path string, state *State) ([][]byte, *State, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, state, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, state, err
	}
	inode := fileInode(fi)

	if state == nil || state.Path != path {
		return nil, &State{Path: path, Inode: inode, Offset: fi.Size()}, nil
	}
	offset := state.Offset
	if state.Inode != inode || fi.Size() < offset {
		offset = 0 // 已轮转：从新文件开头读。轮转前最后一小段未读内容会丢失。
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, state, err
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxReadPerCycle))
	if err != nil {
		return nil, state, err
	}
	consumed := int64(len(data))
	switch i := bytes.LastIndexByte(data, '\n'); {
	case i >= 0:
		data = data[:i+1]
		consumed = int64(i + 1)
	case len(data) == MaxReadPerCycle:
		data = nil // 单行超过上限，丢弃这一段，避免永远卡在这里
	default:
		data, consumed = nil, 0 // 末尾半行留到下一次
	}

	var lines [][]byte
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines, &State{Path: path, Inode: inode, Offset: offset + consumed}, nil
}
