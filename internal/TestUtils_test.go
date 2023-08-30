package internal

import (
	"io"
	"log"
	"time"
)

type testTask struct {
	name string
}

func (tt testTask) ExecuteTask() error {
	return nil
}

func (tt testTask) GetNewTimer() time.Timer {
	return *time.NewTimer(time.Second * 1)
}

func (tt testTask) GetTaskName() string {
	return tt.name
}

type WriterWithCounter struct {
	writer io.Writer
	count  int
}

func (cw WriterWithCounter) Write(p []byte) (n int, err error) {
	cw.count++
	return cw.writer.Write(p)
}

func NewWriterWithCounter() *WriterWithCounter {
	return &WriterWithCounter{
		writer: log.Writer(),
	}
}
