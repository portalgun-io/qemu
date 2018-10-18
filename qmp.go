package qemu

import (
	"bufio"
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"context"
	"strings"
)

type QMPLog interface {
	V(int32) bool
	Infof(string, ...interface{})
	Warningf(string, ...interface{})
	Errorf(string, ...interface{})
}

type qmpNullLogger struct{}

func (l qmpNullLogger) V(level int32) bool {
	return false
}

func (l qmpNullLogger) Infof(format string, v ...interface{}) {
}

func (l qmpNullLogger) Warningf(format string, v ...interface{}) {
}

func (l qmpNullLogger) Errorf(format string, v ...interface{}) {
}

type QMPConfig struct {
	EventCh chan<- QMPEvent
	Logger  QMPLog
}

type qmpEventFilter struct {
	eventName string
	dataKey   string
	dataValue string
}

type QMPEvent struct {
	Name      string
	Data      map[string]interface{}
	Timestamp time.Time
}

type qmpResult struct {
	response interface{}
	err      error
}

type qmpCommand struct {
	ctx            context.Context
	res            chan qmpResult
	name           string
	args           map[string]interface{}
	filter         *qmpEventFilter
	resultReceived bool
	oob            []byte
}

type QMP struct {
	cmdCh          chan qmpCommand
	conn           io.ReadWriteCloser
	cfg            QMPConfig
	connectedCh    chan<- *QMPVersion
	disconnectedCh chan struct{}
	version        *QMPVersion
}

type QMPVersion struct {
	Major        int
	Minor        int
	Micro        int
	Capabilities []string
}

type CPUProperties struct {
	Node   int `json:"node-id"`
	Socket int `json:"socket-id"`
	Core   int `json:"core-id"`
	Thread int `json:"thread-id"`
}

type HotpluggableCPU struct {
	Type       string        `json:"type"`
	VcpusCount int           `json:"vcpus-count"`
	Properties CPUProperties `json:"props"`
	QOMPath    string        `json:"qom-path"`
}

type MemoryDevicesData struct {
	Slot         int    `json:"slot"`
	Node         int    `json:"node"`
	Addr         uint64 `json:"addr"`
	Memdev       string `json:"memdev"`
	ID           string `json:"id"`
	Hotpluggable bool   `json:"hotpluggable"`
	Hotplugged   bool   `json:"hotplugged"`
	Size         uint64 `json:"size"`
}

type MemoryDevices struct {
	Data MemoryDevicesData `json:"data"`
	Type string            `json:"type"`
}

type CPUInfo struct {
	CPU      int           `json:"CPU"`
	Current  bool          `json:"current"`
	Halted   bool          `json:"halted"`
	QomPath  string        `json:"qom_path"`
	Arch     string        `json:"arch"`
	Pc       int           `json:"pc"`
	ThreadID int           `json:"thread_id"`
	Props    CPUProperties `json:"props"`
}

type CPUInfoFast struct {
	CPUIndex int           `json:"cpu-index"`
	QomPath  string        `json:"qom-path"`
	Arch     string        `json:"arch"`
	ThreadID int           `json:"thread-id"`
	Target   string        `json:"target"`
	Props    CPUProperties `json:"props"`
}

type MigrationRAM struct {
	Total            int64 `json:"total"`
	Remaining        int64 `json:"remaining"`
	Transferred      int64 `json:"transferred"`
	TotalTime        int64 `json:"total-time"`
	SetupTime        int64 `json:"setup-time"`
	ExpectedDowntime int64 `json:"expected-downtime"`
	Duplicate        int64 `json:"duplicate"`
	Normal           int64 `json:"normal"`
	NormalBytes      int64 `json:"normal-bytes"`
	DirtySyncCount   int64 `json:"dirty-sync-count"`
}

type MigrationDisk struct {
	Total       int64 `json:"total"`
	Remaining   int64 `json:"remaining"`
	Transferred int64 `json:"transferred"`
}

type MigrationXbzrleCache struct {
	CacheSize     int64 `json:"cache-size"`
	Bytes         int64 `json:"bytes"`
	Pages         int64 `json:"pages"`
	CacheMiss     int64 `json:"cache-miss"`
	CacheMissRate int64 `json:"cache-miss-rate"`
	Overflow      int64 `json:"overflow"`
}

type MigrationStatus struct {
	Status       string                   `json:"status"`
	Capabilities []map[string]interface{} `json:"capabilities,omitempty"`
	RAM          MigrationRAM             `json:"ram,omitempty"`
	Disk         MigrationDisk            `json:"disk,omitempty"`
	XbzrleCache  MigrationXbzrleCache     `json:"xbzrle-cache,omitempty"`
}

func (q *QMP) readLoop(fromVMCh chan<- []byte) {
	scanner := bufio.NewScanner(q.conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		if q.cfg.Logger.V(1) {
			q.cfg.Logger.Infof("%s", string(line))
		}
		fromVMCh <- line
	}
	close(fromVMCh)
}

func (q *QMP) processQMPEvent(cmdQueue *list.List, name interface{}, data interface{},
	timestamp interface{}) {

	strname, ok := name.(string)
	if !ok {
		return
	}

	var eventData map[string]interface{}
	if data != nil {
		eventData, _ = data.(map[string]interface{})
	}

	cmdEl := cmdQueue.Front()
	if cmdEl != nil {
		cmd := cmdEl.Value.(*qmpCommand)
		filter := cmd.filter
		if filter != nil {
			if filter.eventName == strname {
				match := filter.dataKey == ""
				if !match && eventData != nil {
					match = eventData[filter.dataKey] == filter.dataValue
				}
				if match {
					if cmd.resultReceived {
						q.finaliseCommand(cmdEl, cmdQueue, true)
					} else {
						cmd.filter = nil
					}
				}
			}
		}
	}

	if q.cfg.EventCh != nil {
		ev := QMPEvent{
			Name: strname,
			Data: eventData,
		}
		if timestamp != nil {
			timestamp, ok := timestamp.(map[string]interface{})
			if ok {
				seconds, _ := timestamp["seconds"].(float64)
				microseconds, _ := timestamp["microseconds"].(float64)
				ev.Timestamp = time.Unix(int64(seconds), int64(microseconds))
			}
		}

		q.cfg.EventCh <- ev
	}
}

func (q *QMP) finaliseCommandWithResponse(cmdEl *list.Element, cmdQueue *list.List, succeeded bool, response interface{}) {
	cmd := cmdEl.Value.(*qmpCommand)
	cmdQueue.Remove(cmdEl)
	select {
	case <-cmd.ctx.Done():
	default:
		if succeeded {
			cmd.res <- qmpResult{response: response}
		} else {
			cmd.res <- qmpResult{err: fmt.Errorf("QMP command failed")}
		}
	}
	if cmdQueue.Len() > 0 {
		q.writeNextQMPCommand(cmdQueue)
	}
}

func (q *QMP) finaliseCommand(cmdEl *list.Element, cmdQueue *list.List, succeeded bool) {
	q.finaliseCommandWithResponse(cmdEl, cmdQueue, succeeded, nil)
}

func (q *QMP) processQMPInput(line []byte, cmdQueue *list.List) {
	var vmData map[string]interface{}
	err := json.Unmarshal(line, &vmData)
	if err != nil {
		q.cfg.Logger.Warningf("Unable to decode response [%s] from VM: %v",
			string(line), err)
		return
	}
	if evname, found := vmData["event"]; found {
		q.processQMPEvent(cmdQueue, evname, vmData["data"], vmData["timestamp"])
		return
	}

	response, succeeded := vmData["return"]
	_, failed := vmData["error"]

	if !succeeded && !failed {
		return
	}

	cmdEl := cmdQueue.Front()
	if cmdEl == nil {
		q.cfg.Logger.Warningf("Unexpected command response received [%s] from VM",
			string(line))
		return
	}
	cmd := cmdEl.Value.(*qmpCommand)
	if failed || cmd.filter == nil {
		q.finaliseCommandWithResponse(cmdEl, cmdQueue, succeeded, response)
	} else {
		cmd.resultReceived = true
	}
}

func currentCommandDoneCh(cmdQueue *list.List) <-chan struct{} {
	cmdEl := cmdQueue.Front()
	if cmdEl == nil {
		return nil
	}
	cmd := cmdEl.Value.(*qmpCommand)
	return cmd.ctx.Done()
}

func (q *QMP) writeNextQMPCommand(cmdQueue *list.List) {
	cmdEl := cmdQueue.Front()
	cmd := cmdEl.Value.(*qmpCommand)
	cmdData := make(map[string]interface{})
	cmdData["execute"] = cmd.name
	if cmd.args != nil {
		cmdData["arguments"] = cmd.args
	}
	encodedCmd, err := json.Marshal(&cmdData)
	if err != nil {
		cmd.res <- qmpResult{
			err: fmt.Errorf("Unable to marhsall command %s: %v",
				cmd.name, err),
		}
		cmdQueue.Remove(cmdEl)
	}
	q.cfg.Logger.Infof("%s", string(encodedCmd))
	encodedCmd = append(encodedCmd, '\n')
	if unixConn, ok := q.conn.(*net.UnixConn); ok && len(cmd.oob) > 0 {
		_, _, err = unixConn.WriteMsgUnix(encodedCmd, cmd.oob, nil)
	} else {
		_, err = q.conn.Write(encodedCmd)
	}

	if err != nil {
		cmd.res <- qmpResult{
			err: fmt.Errorf("Unable to write command to qmp socket %v", err),
		}
		cmdQueue.Remove(cmdEl)
	}
}

func failOutstandingCommands(cmdQueue *list.List) {
	for e := cmdQueue.Front(); e != nil; e = e.Next() {
		cmd := e.Value.(*qmpCommand)
		select {
		case cmd.res <- qmpResult{
			err: errors.New("exitting QMP loop, command cancelled"),
		}:
		case <-cmd.ctx.Done():
		}
	}
}

func (q *QMP) cancelCurrentCommand(cmdQueue *list.List) {
	cmdEl := cmdQueue.Front()
	cmd := cmdEl.Value.(*qmpCommand)
	if cmd.resultReceived {
		q.finaliseCommand(cmdEl, cmdQueue, false)
	} else {
		cmd.filter = nil
	}
}

func (q *QMP) parseVersion(version []byte) *QMPVersion {
	var qmp map[string]interface{}
	err := json.Unmarshal(version, &qmp)
	if err != nil {
		q.cfg.Logger.Errorf("Invalid QMP greeting: %s", string(version))
		return nil
	}

	versionMap := qmp
	for _, k := range []string{"QMP", "version", "qemu"} {
		versionMap, _ = versionMap[k].(map[string]interface{})
		if versionMap == nil {
			q.cfg.Logger.Errorf("Invalid QMP greeting: %s", string(version))
			return nil
		}
	}

	micro, _ := versionMap["micro"].(float64)
	minor, _ := versionMap["minor"].(float64)
	major, _ := versionMap["major"].(float64)
	capabilities, _ := qmp["QMP"].(map[string]interface{})["capabilities"].([]interface{})
	stringcaps := make([]string, 0, len(capabilities))
	for _, c := range capabilities {
		if cap, ok := c.(string); ok {
			stringcaps = append(stringcaps, cap)
		}
	}
	return &QMPVersion{Major: int(major),
		Minor:        int(minor),
		Micro:        int(micro),
		Capabilities: stringcaps,
	}
}

func (q *QMP) mainLoop() {
	cmdQueue := list.New().Init()
	fromVMCh := make(chan []byte)
	go q.readLoop(fromVMCh)

	defer func() {
		if q.cfg.EventCh != nil {
			close(q.cfg.EventCh)
		}
		_ = q.conn.Close()
		_ = <-fromVMCh
		failOutstandingCommands(cmdQueue)
		close(q.disconnectedCh)
	}()

	var version []byte
	var cmdDoneCh <-chan struct{}

DONE:
	for {
		var ok bool
		select {
		case cmd, ok := <-q.cmdCh:
			if !ok {
				return
			}
			_ = cmdQueue.PushBack(&cmd)
		case version, ok = <-fromVMCh:
			if !ok {
				return
			}
			if cmdQueue.Len() >= 1 {
				q.writeNextQMPCommand(cmdQueue)
				cmdDoneCh = currentCommandDoneCh(cmdQueue)
			}
			break DONE
		}
	}

	q.connectedCh <- q.parseVersion(version)

	for {
		select {
		case cmd, ok := <-q.cmdCh:
			if !ok {
				return
			}
			_ = cmdQueue.PushBack(&cmd)
			if cmdQueue.Len() == 1 {
				q.writeNextQMPCommand(cmdQueue)
				cmdDoneCh = currentCommandDoneCh(cmdQueue)
			}
		case line, ok := <-fromVMCh:
			if !ok {
				return
			}
			q.processQMPInput(line, cmdQueue)
			cmdDoneCh = currentCommandDoneCh(cmdQueue)
		case <-cmdDoneCh:
			q.cancelCurrentCommand(cmdQueue)
			cmdDoneCh = currentCommandDoneCh(cmdQueue)
		}
	}
}

func startQMPLoop(conn io.ReadWriteCloser, cfg QMPConfig,
	connectedCh chan<- *QMPVersion, disconnectedCh chan struct{}) *QMP {
	q := &QMP{
		cmdCh:          make(chan qmpCommand),
		conn:           conn,
		cfg:            cfg,
		connectedCh:    connectedCh,
		disconnectedCh: disconnectedCh,
	}
	go q.mainLoop()
	return q
}

func (q *QMP) executeCommandWithResponse(ctx context.Context, name string, args map[string]interface{},
	oob []byte, filter *qmpEventFilter) (interface{}, error) {
	var err error
	var response interface{}
	resCh := make(chan qmpResult)
	select {
	case <-q.disconnectedCh:
		err = errors.New("exitting QMP loop, command cancelled")
	case q.cmdCh <- qmpCommand{
		ctx:    ctx,
		res:    resCh,
		name:   name,
		args:   args,
		filter: filter,
		oob:    oob,
	}:
	}

	if err != nil {
		return response, err
	}

	select {
	case res := <-resCh:
		err = res.err
		response = res.response
	case <-ctx.Done():
		err = ctx.Err()
	}

	return response, err
}

func (q *QMP) executeCommand(ctx context.Context, name string, args map[string]interface{},
	filter *qmpEventFilter) error {

	_, err := q.executeCommandWithResponse(ctx, name, args, nil, filter)
	return err
}

func QMPStart(ctx context.Context, socket string, cfg QMPConfig, disconnectedCh chan struct{}) (*QMP, *QMPVersion, error) {
	if cfg.Logger == nil {
		cfg.Logger = qmpNullLogger{}
	}
	dialer := net.Dialer{Cancel: ctx.Done()}
	conn, err := dialer.Dial("unix", socket)
	if err != nil {
		cfg.Logger.Warningf("Unable to connect to unix socket (%s): %v", socket, err)
		close(disconnectedCh)
		return nil, nil, err
	}

	connectedCh := make(chan *QMPVersion)

	q := startQMPLoop(conn, cfg, connectedCh, disconnectedCh)
	select {
	case <-ctx.Done():
		q.Shutdown()
		<-disconnectedCh
		return nil, nil, fmt.Errorf("Canceled by caller")
	case <-disconnectedCh:
		return nil, nil, fmt.Errorf("Lost connection to VM")
	case q.version = <-connectedCh:
		if q.version == nil {
			return nil, nil, fmt.Errorf("Failed to find QMP version information")
		}
	}

	return q, q.version, nil
}

func (q *QMP) Shutdown() {
	close(q.cmdCh)
}

func (q *QMP) ExecuteQMPCapabilities(ctx context.Context) error {
	return q.executeCommand(ctx, "qmp_capabilities", nil, nil)
}

func (q *QMP) ExecuteStop(ctx context.Context) error {
	return q.executeCommand(ctx, "stop", nil, nil)
}

func (q *QMP) ExecuteCont(ctx context.Context) error {
	return q.executeCommand(ctx, "cont", nil, nil)
}

func (q *QMP) ExecuteSystemPowerdown(ctx context.Context) error {
	filter := &qmpEventFilter{
		eventName: "SHUTDOWN",
	}
	return q.executeCommand(ctx, "system_powerdown", nil, filter)
}

func (q *QMP) ExecuteQuit(ctx context.Context) error {
	return q.executeCommand(ctx, "quit", nil, nil)
}

func (q *QMP) ExecuteBlockdevAdd(ctx context.Context, device, blockdevID string) error {
	var args map[string]interface{}

	blockdevArgs := map[string]interface{}{
		"driver": "raw",
		"file": map[string]interface{}{
			"driver":   "file",
			"filename": device,
		},
	}

	if q.version.Major > 2 || (q.version.Major == 2 && q.version.Minor >= 8) {
		blockdevArgs["node-name"] = blockdevID
		args = blockdevArgs
	} else {
		blockdevArgs["id"] = blockdevID
		args = map[string]interface{}{
			"options": blockdevArgs,
		}
	}

	return q.executeCommand(ctx, "blockdev-add", args, nil)
}

func (q *QMP) ExecuteDeviceAdd(ctx context.Context, blockdevID, devID, driver, bus, romfile string, shared bool) error {
	args := map[string]interface{}{
		"id":     devID,
		"driver": driver,
		"drive":  blockdevID,
	}
	if bus != "" {
		args["bus"] = bus
	}
	if shared && (q.version.Major > 2 || (q.version.Major == 2 && q.version.Minor >= 10)) {
		args["share-rw"] = "on"
	}
	if isVirtioPCI[DeviceDriver(driver)] {
		args["romfile"] = romfile
	}

	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteSCSIDeviceAdd(ctx context.Context, blockdevID, devID, driver, bus, romfile string, scsiID, lun int, shared bool) error {
	drivers := []string{"scsi-hd", "scsi-cd", "scsi-disk"}
	isSCSIDriver := false
	for _, d := range drivers {
		if driver == d {
			isSCSIDriver = true
			break
		}
	}

	if !isSCSIDriver {
		return fmt.Errorf("Invalid SCSI driver provided %s", driver)
	}

	args := map[string]interface{}{
		"id":     devID,
		"driver": driver,
		"drive":  blockdevID,
		"bus":    bus,
	}
	if scsiID >= 0 {
		args["scsi-id"] = scsiID
	}
	if lun >= 0 {
		args["lun"] = lun
	}
	if shared && (q.version.Major > 2 || (q.version.Major == 2 && q.version.Minor >= 10)) {
		args["share-rw"] = "on"
	}
	if isVirtioPCI[DeviceDriver(driver)] {
		args["romfile"] = romfile
	}

	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteBlockdevDel(ctx context.Context, blockdevID string) error {
	args := map[string]interface{}{}

	if q.version.Major > 2 || (q.version.Major == 2 && q.version.Minor >= 9) {
		args["node-name"] = blockdevID
		return q.executeCommand(ctx, "blockdev-del", args, nil)
	}

	if q.version.Major == 2 && q.version.Minor == 8 {
		args["node-name"] = blockdevID
	} else {
		args["id"] = blockdevID
	}

	return q.executeCommand(ctx, "x-blockdev-del", args, nil)
}

func (q *QMP) ExecuteNetdevAdd(ctx context.Context, netdevType, netdevID, ifname, downscript, script string, queues int) error {
	args := map[string]interface{}{
		"type":       netdevType,
		"id":         netdevID,
		"ifname":     ifname,
		"downscript": downscript,
		"script":     script,
	}
	if queues > 1 {
		args["queues"] = queues
	}

	return q.executeCommand(ctx, "netdev_add", args, nil)
}

func (q *QMP) ExecuteNetdevChardevAdd(ctx context.Context, netdevType, netdevID, chardev string, queues int) error {
	args := map[string]interface{}{
		"type":    netdevType,
		"id":      netdevID,
		"chardev": chardev,
	}
	if queues > 1 {
		args["queues"] = queues
	}

	return q.executeCommand(ctx, "netdev_add", args, nil)
}

func (q *QMP) ExecuteNetdevAddByFds(ctx context.Context, netdevType, netdevID string, fdNames, vhostFdNames []string) error {
	fdNameStr := strings.Join(fdNames, ":")
	args := map[string]interface{}{
		"type": netdevType,
		"id":   netdevID,
		"fds":  fdNameStr,
	}
	if len(vhostFdNames) > 0 {
		vhostFdNameStr := strings.Join(vhostFdNames, ":")
		args["vhost"] = "on"
		args["vhostfds"] = vhostFdNameStr
	}

	return q.executeCommand(ctx, "netdev_add", args, nil)
}

func (q *QMP) ExecuteNetdevDel(ctx context.Context, netdevID string) error {
	args := map[string]interface{}{
		"id": netdevID,
	}
	return q.executeCommand(ctx, "netdev_del", args, nil)
}

func (q *QMP) ExecuteNetPCIDeviceAdd(ctx context.Context, netdevID, devID, macAddr, addr, bus, romfile string, queues int) error {
	args := map[string]interface{}{
		"id":      devID,
		"driver":  VirtioNetPCI,
		"romfile": romfile,
	}

	if bus != "" {
		args["bus"] = bus
	}
	if addr != "" {
		args["addr"] = addr
	}
	if macAddr != "" {
		args["mac"] = macAddr
	}
	if netdevID != "" {
		args["netdev"] = netdevID
	}

	if queues > 0 {
		args["mq"] = "on"
		args["vectors"] = 2*queues + 2
	}

	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteDeviceDel(ctx context.Context, devID string) error {
	args := map[string]interface{}{
		"id": devID,
	}
	filter := &qmpEventFilter{
		eventName: "DEVICE_DELETED",
		dataKey:   "device",
		dataValue: devID,
	}
	return q.executeCommand(ctx, "device_del", args, filter)
}

func (q *QMP) ExecutePCIDeviceAdd(ctx context.Context, blockdevID, devID, driver, addr, bus, romfile string, shared bool) error {
	args := map[string]interface{}{
		"id":     devID,
		"driver": driver,
		"drive":  blockdevID,
		"addr":   addr,
	}
	if bus != "" {
		args["bus"] = bus
	}
	if shared && (q.version.Major > 2 || (q.version.Major == 2 && q.version.Minor >= 10)) {
		args["share-rw"] = "on"
	}
	if isVirtioPCI[DeviceDriver(driver)] {
		args["romfile"] = romfile
	}

	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteVFIODeviceAdd(ctx context.Context, devID, bdf, romfile string) error {
	args := map[string]interface{}{
		"id":      devID,
		"driver":  "vfio-pci",
		"host":    bdf,
		"romfile": romfile,
	}
	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecutePCIVFIODeviceAdd(ctx context.Context, devID, bdf, addr, bus, romfile string) error {
	args := map[string]interface{}{
		"id":      devID,
		"driver":  "vfio-pci",
		"host":    bdf,
		"addr":    addr,
		"romfile": romfile,
	}
	if bus != "" {
		args["bus"] = bus
	}
	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecutePCIVFIOMediatedDeviceAdd(ctx context.Context, devID, sysfsdev, addr, bus, romfile string) error {
	args := map[string]interface{}{
		"id":       devID,
		"driver":   "vfio-pci",
		"sysfsdev": sysfsdev,
		"romfile":  romfile,
	}
	if bus != "" {
		args["bus"] = bus
	}
	if addr != "" {
		args["addr"] = addr
	}
	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteCPUDeviceAdd(ctx context.Context, driver, cpuID, socketID, coreID, threadID, romfile string) error {
	args := map[string]interface{}{
		"driver":    driver,
		"id":        cpuID,
		"socket-id": socketID,
		"core-id":   coreID,
		"thread-id": threadID,
	}

	if isVirtioPCI[DeviceDriver(driver)] {
		args["romfile"] = romfile
	}

	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteQueryHotpluggableCPUs(ctx context.Context) ([]HotpluggableCPU, error) {
	response, err := q.executeCommandWithResponse(ctx, "query-hotpluggable-cpus", nil, nil, nil)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract CPU information: %v", err)
	}

	var cpus []HotpluggableCPU
	if err = json.Unmarshal(data, &cpus); err != nil {
		return nil, fmt.Errorf("Unable to convert json to hotpluggable CPU: %v", err)
	}

	return cpus, nil
}

func (q *QMP) ExecSetMigrationCaps(ctx context.Context, caps []map[string]interface{}) error {
	args := map[string]interface{}{
		"capabilities": caps,
	}

	return q.executeCommand(ctx, "migrate-set-capabilities", args, nil)
}

func (q *QMP) ExecSetMigrateArguments(ctx context.Context, url string) error {
	args := map[string]interface{}{
		"uri": url,
	}

	return q.executeCommand(ctx, "migrate", args, nil)
}

func (q *QMP) ExecQueryMemoryDevices(ctx context.Context) ([]MemoryDevices, error) {
	response, err := q.executeCommandWithResponse(ctx, "query-memory-devices", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract memory devices information: %v", err)
	}

	var memoryDevices []MemoryDevices
	if err = json.Unmarshal(data, &memoryDevices); err != nil {
		return nil, fmt.Errorf("unable to convert json to memory devices: %v", err)
	}

	return memoryDevices, nil
}

func (q *QMP) ExecQueryCpus(ctx context.Context) ([]CPUInfo, error) {
	response, err := q.executeCommandWithResponse(ctx, "query-cpus", nil, nil, nil)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract memory devices information: %v", err)
	}

	var cpuInfo []CPUInfo
	if err = json.Unmarshal(data, &cpuInfo); err != nil {
		return nil, fmt.Errorf("unable to convert json to CPUInfo: %v", err)
	}

	return cpuInfo, nil
}

func (q *QMP) ExecQueryCpusFast(ctx context.Context) ([]CPUInfoFast, error) {
	response, err := q.executeCommandWithResponse(ctx, "query-cpus-fast", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract memory devices information: %v", err)
	}

	var cpuInfoFast []CPUInfoFast
	if err = json.Unmarshal(data, &cpuInfoFast); err != nil {
		return nil, fmt.Errorf("unable to convert json to CPUInfoFast: %v", err)
	}

	return cpuInfoFast, nil
}

func (q *QMP) ExecHotplugMemory(ctx context.Context, qomtype, id, mempath string, size int) error {
	args := map[string]interface{}{
		"qom-type": qomtype,
		"id":       id,
		"props":    map[string]interface{}{"size": uint64(size) << 20},
	}
	if mempath != "" {
		args["mem-path"] = mempath
	}
	err := q.executeCommand(ctx, "object-add", args, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			q.cfg.Logger.Errorf("Unable to hotplug memory device: %v", err)
			err = q.executeCommand(ctx, "object-del", map[string]interface{}{"id": id}, nil)
			if err != nil {
				q.cfg.Logger.Warningf("Unable to clean up memory object: %v", err)
			}
		}
	}()

	args = map[string]interface{}{
		"driver": "pc-dimm",
		"id":     "dimm" + id,
		"memdev": id,
	}
	err = q.executeCommand(ctx, "device_add", args, nil)

	return err
}

func (q *QMP) ExecuteBalloon(ctx context.Context, bytes uint64) error {
	args := map[string]interface{}{
		"value": bytes,
	}
	return q.executeCommand(ctx, "balloon", args, nil)
}

func (q *QMP) ExecutePCIVSockAdd(ctx context.Context, id, guestCID, vhostfd, addr, bus, romfile string, disableModern bool) error {
	args := map[string]interface{}{
		"driver":    VHostVSockPCI,
		"id":        id,
		"guest-cid": guestCID,
		"vhostfd":   vhostfd,
		"addr":      addr,
		"romfile":   romfile,
	}

	if bus != "" {
		args["bus"] = bus
	}

	if disableModern {
		args["disable-modern"] = disableModern
	}

	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteGetFD(ctx context.Context, fdname string, fd *os.File) error {
	oob := syscall.UnixRights(int(fd.Fd()))
	args := map[string]interface{}{
		"fdname": fdname,
	}

	_, err := q.executeCommandWithResponse(ctx, "getfd", args, oob, nil)
	return err
}

func (q *QMP) ExecuteCharDevUnixSocketAdd(ctx context.Context, id, path string, wait, server bool) error {
	args := map[string]interface{}{
		"id": id,
		"backend": map[string]interface{}{
			"type": "socket",
			"data": map[string]interface{}{
				"wait":   wait,
				"server": server,
				"addr": map[string]interface{}{
					"type": "unix",
					"data": map[string]interface{}{
						"path": path,
					},
				},
			},
		},
	}
	return q.executeCommand(ctx, "chardev-add", args, nil)
}

func (q *QMP) ExecuteVirtSerialPortAdd(ctx context.Context, id, name, chardev string) error {
	args := map[string]interface{}{
		"driver":  VirtioSerialPort,
		"id":      id,
		"name":    name,
		"chardev": chardev,
	}

	return q.executeCommand(ctx, "device_add", args, nil)
}

func (q *QMP) ExecuteQueryMigration(ctx context.Context) (MigrationStatus, error) {
	response, err := q.executeCommandWithResponse(ctx, "query-migrate", nil, nil, nil)
	if err != nil {
		return MigrationStatus{}, err
	}

	data, err := json.Marshal(response)
	if err != nil {
		return MigrationStatus{}, fmt.Errorf("Unable to extract migrate status information: %v", err)
	}

	var status MigrationStatus
	if err = json.Unmarshal(data, &status); err != nil {
		return MigrationStatus{}, fmt.Errorf("Unable to convert migrate status information: %v", err)
	}

	return status, nil
}
