package internal

import (
	"errors"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"
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
	var wg sync.WaitGroup

	if len(s.taskRegistry) == 0 {
		log.Println("no task scheduled. cannot start tasks")
		return
	}

	for _, value := range s.taskRegistry {
		wg.Add(1)
		go ScheduleTask(value, s.errChan, &wg)
	}

	s.waitForExit(s.errChan, s.exitChan, &wg)
	log.Println("tasks completed!")
}

func (s *Scheduler) waitForExit(errChan chan ErrorEvent, exitChan chan os.Signal, wg *sync.WaitGroup) {
	for {
		select {
		case err := <-errChan:
			logError(err)
		case <-exitChan:
			for _, job := range s.taskRegistry {
				log.Printf("Requesting %s to stop!\n", job.GetTaskName())
				job.StopTask()
			}

			wg.Wait()
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

	log.Printf("task finished : %s (exit requested : %t)\n", task.GetTaskName(), task.IsStopped())

	for {
		select {
		case <-task.StopChan():
		case <-time.After(task.GetDuration()):
			return nil
		}
	}
}

func ScheduleTask(task Task, errChan chan ErrorEvent, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		err := ExecuteTaskWrapper(task)
		if err != nil {
			errChan <- ErrorEvent{err, task.GetTaskName()}
			return
		}

		if task.IsStopped() {
			task.StopChan() <- struct{}{}
			return
		}
	}
}
