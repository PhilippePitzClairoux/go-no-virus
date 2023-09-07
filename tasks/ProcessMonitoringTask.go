package tasks

import (
	"endpointSecurityAgent/internal"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
	"regexp"
	"strings"
	"time"
)

type ProcessMonitoring struct {
	// configuration
	AuditAllProcesses        bool     `yaml:"audit_all_processes"`
	ExcludeSpecificProcesses []string `yaml:"exclude_specific_processes"`
	SensitiveFiles           []string `yaml:"sensitive_files"`
	stopTask                 bool
}

type aggregateProcessInfo struct {
	children              []*process.Process
	parent                *process.Process
	background            bool
	cmdline               []string
	connections           []net.ConnectionStat
	memInfo               *process.MemoryInfoStat
	files                 []process.OpenFilesStat
	suspiciousConnections []string
	suspiciousFiles       []string
}

var isLocalhostIp = regexp.MustCompile("(0.0.0.0|127.0.0.1|:+)")

/*
Define function to get aggregateProcessInfo field (suspicion and data) to make some parts of the code more generic and
reduce duplication
*/
type aggregateProcessInfoField func(pmt *aggregateProcessInfo) (string, []string)

func (t *ProcessMonitoring) StopTask() {
	t.stopTask = true
}

func (t *ProcessMonitoring) IsStopped() bool {
	return t.stopTask
}

// fileField returns suspiciousFiles from aggregateProcessInfo
func fileField(api *aggregateProcessInfo) (string, []string) {
	return "file", api.suspiciousFiles
}

// connectionField returns suspiciousConnections from aggregateProcessInfo
func connectionField(api *aggregateProcessInfo) (string, []string) {
	return "network", api.suspiciousConnections
}

// ExecuteTask executes the ProcessMonitoring
func (t *ProcessMonitoring) ExecuteTask() error {

	processes, err := getProcList()
	if err != nil {
		return err
	}

	err = t.auditProcesses(processes)
	if err != nil {
		return err
	}

	return nil
}

func (t *ProcessMonitoring) GetDuration() time.Duration {
	return 2 * time.Minute
}

// GetTaskName - return task name
func (t *ProcessMonitoring) GetTaskName() string {
	return "ProcessMonitoring"
}

// getProcList returns all the running process on the current operating system
func getProcList() ([]*process.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	return processes, nil
}

// auditProcesses function that goes through all the processes and audits them. Will mark process as suspicious
// if there's outgoing connections and/or if the process is accessing sensitive files (path matches sensitive_files in configuration) .
// processes that match exclude_specific_processes will be ignored.
func (t *ProcessMonitoring) auditProcesses(processes []*process.Process) error {
	suspiciousProcesses := make(map[int32]*aggregateProcessInfo)

	for _, proc := range processes {

		if t.stopTask {
			return nil
		}

		info := gatherProcessInformation(proc)

		if t.ignoreProc(info.cmdline) {
			continue
		}

		t.addSuspiciousConnections(info, &suspiciousProcesses, proc)
		t.addSuspiciousFiles(info, &suspiciousProcesses, proc)
	}

	if len(suspiciousProcesses) > 0 {
		err := t.handleSuspiciousProcess(suspiciousProcesses, connectionField)
		if err != nil {
			return err
		}

		err = t.handleSuspiciousProcess(suspiciousProcesses, fileField)
		if err != nil {
			return err
		}
	}

	return nil
}

// handleSuspiciousProcess will get parentProcess (if it exists) and store event into the database for later review
func (t *ProcessMonitoring) handleSuspiciousProcess(suspiciousProcess map[int32]*aggregateProcessInfo, getSuspicionAndData aggregateProcessInfoField) error {
	for key, processInfo := range suspiciousProcess {
		pid := key
		parentProcess := getParentProcess(key)

		if parentProcess != nil && parentProcess.Pid != key {
			pid = parentProcess.Pid
		}

		suspicion, data := getSuspicionAndData(processInfo)
		err := storeSuspiciousProcess(pid, processInfo, suspicion, data)
		if err != nil {
			return err
		}
	}
	return nil
}

// will add a suspiciousConnection to aggregateProcessInfo if it's status is not NONE and the IP isn't localhost
func (t *ProcessMonitoring) addSuspiciousConnections(processInfo *aggregateProcessInfo, suspiciousProcessConnections *map[int32]*aggregateProcessInfo, proc *process.Process) {
	for _, conn := range processInfo.connections {
		if conn.Status != "NONE" && !isLocalhostIp.MatchString(conn.Raddr.IP) {
			if _, ok := (*suspiciousProcessConnections)[proc.Pid]; !ok {
				(*suspiciousProcessConnections)[proc.Pid] = processInfo
			}
			processInfo.suspiciousConnections = append(processInfo.suspiciousConnections, conn.Raddr.String())
		}
	}
}

// getParentProcess will GetParentProcess() untill we find the command that started the problematic process
func getParentProcess(key int32) *process.Process {
	proc, err := process.NewProcess(key)
	if err != nil {
		return nil
	}

	for {
		cmdLine, err := proc.CmdlineSlice()
		if len(cmdLine) == 0 && err == nil {
			parent, err := proc.Parent()
			if err != nil {
				return proc
			}
			proc = parent
		} else {
			return proc
		}
	}
}

// ignoreProc checks if the process is contained in ExcludeSpecificProcesses
func (t *ProcessMonitoring) ignoreProc(procName []string) bool {
	if len(procName) == 0 {
		// if there's no proc name, it's probably a sub-process or a thread
		return false
	}
	for _, name := range t.ExcludeSpecificProcesses {
		if strings.Contains(procName[0], name) {
			return true
		}
	}
	return false
}

// addSuspiciousFile will add an entry to aggregateProcessInfo if we consider the process suspicious
func (t *ProcessMonitoring) addSuspiciousFiles(procInfo *aggregateProcessInfo, m *map[int32]*aggregateProcessInfo, proc *process.Process) {
	if _, ok := (*m)[proc.Pid]; !ok {
		(*m)[proc.Pid] = procInfo
	}

	var suspiciousFileArrayReference = &((*m)[proc.Pid].suspiciousFiles)
	for _, file := range procInfo.files {
		if t.suspiciousFile(file.Path) {
			*suspiciousFileArrayReference = append(*suspiciousFileArrayReference, file.Path)
		}
	}
}

// suspiciousFile whether the filepath matches an entry in sensitive_files
func (t *ProcessMonitoring) suspiciousFile(path string) bool {
	for _, file := range t.SensitiveFiles {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}

// gatherProcessInformation returns an aggregateProcessInfo for a process.Process
func gatherProcessInformation(proc *process.Process) *aggregateProcessInfo {
	children, _ := proc.Children()
	parent, _ := proc.Parent()
	background, _ := proc.Background()
	cmdline, _ := proc.CmdlineSlice()
	connections, _ := proc.Connections()
	info, _ := proc.MemoryInfo()
	files, _ := proc.OpenFiles()

	return &aggregateProcessInfo{
		children,
		parent,
		background,
		cmdline,
		connections,
		info,
		files,
		make([]string, 0),
		make([]string, 0),
	}
}

// storeSuspiciousProcess will store in the database the process we've marked as suspicious (either for network or file reasons)
func storeSuspiciousProcess(pid int32, info *aggregateProcessInfo, suspicionType string, data []string) error {
	if len(data) == 0 {
		// nothing to do - skip
		return nil
	}

	db := internal.GetDatabase()
	defer db.Close()

	query := `INSERT INTO suspicious_process (pid, cmd_line, suspicion_type, data) VALUES `
	var values []interface{}

	for _, cause := range data {
		query += "(?, ?, ?, ?),"
		values = append(values, pid, strings.Join(info.cmdline, " "), suspicionType, cause)
	}

	// remove extra ,
	query = strings.TrimSuffix(query, ",")
	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()
	_, err = stmt.Exec(values...)
	return err

}
