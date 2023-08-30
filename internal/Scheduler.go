package internal

import "time"

type Task interface {
	ExecuteTask() error
	GetNewTimer() time.Timer
	GetTaskName() string
}
