package internal

import (
	"io"
	"log"
	"time"
)

type testTask struct {
	name     string
	stopTask bool
}

func (tt *testTask) StopChan() chan interface{} {
	return nil
}

// always false
func (tt *testTask) IsStopped() bool {
	return tt.stopTask
}

// do nothing
func (tt *testTask) StopTask() {
	tt.stopTask = true
}

func (tt *testTask) ExecuteTask() error {
	return nil
}

func (tt *testTask) GetDuration() time.Duration {
	return time.Second * 1
}

func (tt *testTask) GetTaskName() string {
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
