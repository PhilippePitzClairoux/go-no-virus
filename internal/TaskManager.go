package internal

import (
	"errors"
	"io"
	"log"
	"os"
	"os/signal"
)

type ErrorEvent struct {
	err      error
	taskName string
}

type Scheduler struct {
	taskRegistry map[string]Task
	errChan      chan ErrorEvent
	exitChan     chan os.Signal
}

func NewScheduler(errChan chan ErrorEvent, exitChan chan os.Signal) *Scheduler {
	return &Scheduler{
		taskRegistry: make(map[string]Task),
		errChan:      errChan,
		exitChan:     exitChan,
	}
}

func NewSchedulerWithCustomWriter(errChan chan ErrorEvent, exitChan chan os.Signal, writer io.Writer) *Scheduler {
	log.SetOutput(writer)
	return NewScheduler(errChan, exitChan)
}

func (s *Scheduler) RegisterTask(task Task) error {
	if value := s.taskRegistry[task.GetTaskName()]; value != nil {
		return errors.New("could not register task since it already exists")
	}

	s.taskRegistry[task.GetTaskName()] = task
	return nil
}

func (s *Scheduler) StartTasks() {
	signal.Notify(s.exitChan, os.Kill)
	signal.Notify(s.exitChan, os.Interrupt)

	if len(s.taskRegistry) == 0 {
		log.Println("no task scheduled. cannot start tasks")
		return
	}

	for _, value := range s.taskRegistry {
		go ScheduleTask(value, s.errChan, s.exitChan)
	}

	waitForExit(s.errChan, s.exitChan)
	log.Println("tasks completed!")
}

func waitForExit(errChan chan ErrorEvent, exitChan chan os.Signal) {
	for {
		select {
		case err := <-errChan:
			logError(err)
		case <-exitChan:
			return
		}
	}
}

func logError(ee ErrorEvent) {
	log.Printf("%s threw an error during it's execution : %s", ee.taskName, ee.err)
}

func ExecuteTaskWrapper(task Task) error {
	log.Printf("starting task : %s\n", task.GetTaskName())
	err := task.ExecuteTask()
	if err != nil {
		log.Printf("error executing task (%s) : %s", task.GetTaskName(), err)
		return err
	}

	// wait for timer to finish before restarting
	log.Printf("%s finished successfully! Waiting for next execution...", task.GetTaskName())
	<-task.GetNewTimer().C
	return nil
}

func ScheduleTask(task Task, errChan chan ErrorEvent, exitChan chan os.Signal) {
	for {
		select {
		case <-exitChan:
			log.Println("got exit signal - closing task")
			return
		default:
			err := ExecuteTaskWrapper(task)
			if err != nil {
				errChan <- ErrorEvent{err, task.GetTaskName()}
				return
			}
		}
	}
}
