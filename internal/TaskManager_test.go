package internal

import (
	"os"
	"testing"
	"time"
)

func TestRegisterTask(t *testing.T) {
	errChan := make(chan ErrorEvent)
	exitChan := make(chan os.Signal)
	scheduler := NewScheduler(errChan, exitChan)
	tasks := []Task{
		testTask{"test1"},
		testTask{"test2"},
		testTask{"test3"},
	}

	for _, task := range tasks {
		err := scheduler.RegisterTask(task)
		if err != nil {
			t.Errorf("could not register task %s : %s", task.GetTaskName(), err)
			t.FailNow()
		} else {
			t.Logf("registed task %s", task.GetTaskName())
		}
	}
}

func TestStartTasks(t *testing.T) {
	errChan := make(chan ErrorEvent)
	exitChan := make(chan os.Signal)
	done := make(chan bool)
	scheduler := NewScheduler(errChan, exitChan)
	tasks := []Task{
		testTask{"test1"},
		testTask{"test2"},
		testTask{"test3"},
	}

	for _, task := range tasks {
		err := scheduler.RegisterTask(task)
		if err != nil {
			t.Errorf("could not register task %s : %s", task.GetTaskName(), err)
			t.FailNow()
		}
	}

	go func(done chan bool, schedule *Scheduler) {
		schedule.StartTasks()
		done <- true
	}(done, scheduler)

	exitChan <- os.Interrupt
	select {
	case <-done:
		//test completed success fully
		return
	case <-time.After(5 * time.Second):
		t.Errorf("Test timeout - StartTask() never finished")
		t.FailNow()
	}
}

func TestSchedulingInterval(t *testing.T) {
	errChan := make(chan ErrorEvent)
	exitChan := make(chan os.Signal)
	done := make(chan bool)
	const expectedTimes = 2
	var counter = NewWriterWithCounter()

	scheduler := NewSchedulerWithCustomWriter(errChan, exitChan, counter)
	tt := []Task{testTask{"test1"}}

	err := scheduler.RegisterTask(tt[0])
	if err != nil {
		t.Errorf("could not register task %s : %s", tt[0].GetTaskName(), err)
		t.FailNow()
	}

	go func(done chan bool, schedule *Scheduler) {
		schedule.StartTasks()
		done <- true
	}(done, scheduler)

	select {
	case <-done:
		if counter.count != expectedTimes {
			t.Errorf("worker did not complete the amount of expected jobs in time")
			t.FailNow()
		}
		//test completed success fully
		return
	case <-time.After(3 * time.Second):
		exitChan <- os.Interrupt
	}

}
