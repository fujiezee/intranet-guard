package chstore

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// 写入批处理：大量 Agent / 探针并发上报时，把同一时间窗口内的事件合并成一次 INSERT。
// ClickHouse 适合少量大批写入；每次上报单独 INSERT 时，上万节点会产生大量小数据分片（Too many parts），
// 而且每次写入都占用一个连接等待落盘。调用方仍然等待自己所在的批次写入完成才返回，
// 所以紧接着的检测查询能看到这批事件，语义与逐条写入相同。
const (
	batchWindow  = 50 * time.Millisecond // 收到第一行后最多再等这么久
	batchMaxRows = 20000
	maxInFlight  = 4 // 同一张表同时进行的 INSERT 数：上一批写入时继续收集下一批
)

type pending struct {
	rows []byte // JSONEachRow
	n    int
	done chan error
}

type batcher struct {
	table string
	write func(ctx context.Context, table string, body []byte) error
	in    chan pending
	sem   chan struct{}
	wg    sync.WaitGroup
}

func newBatcher(table string, write func(context.Context, string, []byte) error) *batcher {
	b := &batcher{table: table, write: write, in: make(chan pending, 1024), sem: make(chan struct{}, maxInFlight)}
	b.wg.Add(1)
	go b.loop()
	return b
}

// add 提交一批行并等待其所在的批次写入完成。调用方的 ctx 取消时提前返回，但这些行仍会写入。
func (b *batcher) add(ctx context.Context, rows []byte, n int) error {
	p := pending{rows: rows, n: n, done: make(chan error, 1)}
	select {
	case b.in <- p:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-p.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *batcher) loop() {
	defer b.wg.Done()
	for {
		first, ok := <-b.in
		if !ok {
			return
		}
		batch := []pending{first}
		n := first.n
		timer := time.NewTimer(batchWindow)
	collect:
		for n < batchMaxRows {
			select {
			case p, ok := <-b.in:
				if !ok {
					break collect
				}
				batch = append(batch, p)
				n += p.n
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		b.sem <- struct{}{}
		b.wg.Add(1)
		go func(batch []pending) {
			defer b.wg.Done()
			defer func() { <-b.sem }()
			var body bytes.Buffer
			for _, p := range batch {
				body.Write(p.rows)
			}
			err := b.write(context.Background(), b.table, body.Bytes())
			for _, p := range batch {
				p.done <- err
			}
		}(batch)
	}
}

// close 写完已提交的行后返回。
func (b *batcher) close() {
	close(b.in)
	b.wg.Wait()
}
