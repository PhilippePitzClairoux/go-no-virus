package internal

import "time"

type Task interface {
	ExecuteTask() error
	GetDuration() time.Duration
	GetTaskName() string
	StopTask()
	IsStopped() bool
	StopChan() chan interface{}
}
