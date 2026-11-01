package chstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBatcher(t *testing.T) {
	var mu sync.Mutex
	var inserts, rows int
	var fail atomic.Bool
	b := newBatcher("t", func(_ context.Context, _ string, body []byte) error {
		mu.Lock()
		defer mu.Unlock()
		inserts++
		rows += bytes.Count(body, []byte("\n"))
		time.Sleep(20 * time.Millisecond)
		if fail.Load() {
			return errors.New("boom")
		}
		return nil
	})

	// 1000 个并发上报，每个 3 行：合并成少数几次写入；每个调用都在写入完成后才返回
	var wg sync.WaitGroup
	var errs atomic.Int32
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := b.add(context.Background(), []byte(fmt.Sprintf("{\"i\":%d}\n{}\n{}\n", i)), 3); err != nil {
				errs.Add(1)
			}
		}(i)
	}
	wg.Wait()
	mu.Lock()
	if rows != 3000 || inserts > 50 || errs.Load() != 0 {
		t.Errorf("rows=%d inserts=%d errs=%d", rows, inserts, errs.Load())
	}
	mu.Unlock()

	// 写入失败时，该批次的每个调用都收到错误（上报方据此重试）
	fail.Store(true)
	if err := b.add(context.Background(), []byte("{}\n"), 1); err == nil {
		t.Error("write error not propagated")
	}
	fail.Store(false)

	// 调用方取消不影响已提交的行写入；关闭时写完
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = b.add(ctx, []byte("{}\n"), 1)
	b.close()
}
