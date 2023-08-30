package internal

import (
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
	"log"
	"regexp"
	"strings"
	"time"
)

type ProcessMonitoringTask struct {
	// configuration
	AuditAllProcesses        bool     `yaml:"audit_all_processes"`
	ExcludeSpecificProcesses []string `yaml:"exclude_specific_processes"`
}

type aggregateProcInfo struct {
	children    []*process.Process
	parent      *process.Process
	background  bool
	cmdline     []string
	connections []net.ConnectionStat
	memInfo     *process.MemoryInfoStat
	files       []process.OpenFilesStat
	sus         []string
}

var isLocalhostIp = regexp.MustCompile("(0.0.0.0|127.0.0.1|:+)")

func (t ProcessMonitoringTask) ExecuteTask() error {

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

func (t ProcessMonitoringTask) GetNewTimer() time.Timer {
	return *time.NewTimer(time.Minute * 2)
}

func (t ProcessMonitoringTask) GetTaskName() string {
	return "ProcessMonitoringTask"
}

func getProcList() ([]*process.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	return processes, nil
}

func (t ProcessMonitoringTask) auditProcesses(processes []*process.Process) error {
	suspiciousProcessConnections := make(map[int32]*aggregateProcInfo)

	for _, proc := range processes {
		info := gatherProcessInformation(proc)

		if t.ignoreProc(info.cmdline) {
			continue
		}

		if len(info.connections) > 0 {
			for _, conn := range info.connections {
				if conn.Status != "NONE" && !isLocalhostIp.MatchString(conn.Raddr.IP) {
					if _, ok := suspiciousProcessConnections[proc.Pid]; !ok {
						suspiciousProcessConnections[proc.Pid] = info
					}
					info.sus = append(info.sus, conn.Raddr.String())
				}
			}
		}
	}

	if len(suspiciousProcessConnections) > 0 {
		log.Println("Found suspicious connections...")
		for key, value := range suspiciousProcessConnections {
			pid := key
			parentProcess := getParentProcess(key)

			if parentProcess != nil && parentProcess.Pid != key {
				pid = parentProcess.Pid
			}

			err := storeSuspiciousConnections(pid, value)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getParentProcess(key int32) *process.Process {
	proc, _ := process.NewProcess(key)

	for {
		cmdLine, _ := proc.CmdlineSlice()
		if len(cmdLine) == 0 {
			parent, _ := proc.Parent()
			proc = parent
		} else {
			return proc
		}
	}
}

func (t ProcessMonitoringTask) ignoreProc(procName []string) bool {
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

func gatherProcessInformation(proc *process.Process) *aggregateProcInfo {
	children, _ := proc.Children()
	parent, _ := proc.Parent()
	background, _ := proc.Background()
	cmdline, _ := proc.CmdlineSlice()
	connections, _ := proc.Connections()
	info, _ := proc.MemoryInfo()
	files, _ := proc.OpenFiles()

	return &aggregateProcInfo{
		children,
		parent,
		background,
		cmdline,
		connections,
		info,
		files,
		make([]string, 0),
	}
}

func storeSuspiciousConnections(pid int32, info *aggregateProcInfo) error {
	db := GetDatabase()
	query := `INSERT INTO suspicious_process (pid, cmd_line, suspicious_connection) VALUES `
	var values []interface{}

	for _, conn := range info.sus {
		query += "(?, ?, ?),"
		values = append(values, pid, strings.Join(info.cmdline, " "), conn)
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
