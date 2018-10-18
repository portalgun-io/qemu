package qemu

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"context"
)

type Machine struct {
	Type         string
	Acceleration string
	Options      string
}

type Device interface {
	Valid() bool
	QemuParams(config *Config) []string
}

type DeviceDriver string

const (
	NVDIMM              DeviceDriver = "nvdimm"
	Virtio9P            DeviceDriver = "virtio-9p-pci"
	VirtioNet           DeviceDriver = "virtio-net"
	VirtioNetPCI        DeviceDriver = "virtio-net-pci"
	VirtioSerial        DeviceDriver = "virtio-serial-pci"
	VirtioBlock         DeviceDriver = "virtio-blk"
	Console             DeviceDriver = "virtconsole"
	VirtioSerialPort    DeviceDriver = "virtserialport"
	VHostVSockPCI       DeviceDriver = "vhost-vsock-pci"
	VirtioRng           DeviceDriver = "virtio-rng"
	VirtioBalloon       DeviceDriver = "virtio-balloon"
	VhostUserSCSI       DeviceDriver = "vhost-user-scsi-pci"
	VhostUserNet        DeviceDriver = "virtio-net-pci"
	VhostUserBlk        DeviceDriver = "vhost-user-blk-pci"
	VfioPCI             DeviceDriver = "vfio-pci"
	VirtioScsiPCI       DeviceDriver = "virtio-scsi-pci"
	PCIBridgeDriver     DeviceDriver = "pci-bridge"
	PCIePCIBridgeDriver DeviceDriver = "pcie-pci-bridge"
)

var isVirtioPCI = map[DeviceDriver]bool{
	NVDIMM:              false,
	Virtio9P:            true,
	VirtioNet:           true,
	VirtioNetPCI:        true,
	VirtioSerial:        true,
	VirtioBlock:         true,
	Console:             false,
	VirtioSerialPort:    false,
	VHostVSockPCI:       true,
	VirtioRng:           true,
	VirtioBalloon:       true,
	VhostUserSCSI:       true,
	VhostUserBlk:        true,
	VfioPCI:             true,
	VirtioScsiPCI:       true,
	PCIBridgeDriver:     true,
	PCIePCIBridgeDriver: true,
}

type ObjectType string

const (
	MemoryBackendFile ObjectType = "memory-backend-file"
)

type Object struct {
	Driver   DeviceDriver
	Type     ObjectType
	ID       string
	DeviceID string
	MemPath  string
	Size     uint64
}

func (object Object) Valid() bool {
	switch object.Type {
	case MemoryBackendFile:
		if object.ID == "" || object.MemPath == "" || object.Size == 0 {
			return false
		}

	default:
		return false
	}

	return true
}

func (object Object) QemuParams(config *Config) []string {
	var objectParams []string
	var deviceParams []string
	var qemuParams []string

	deviceParams = append(deviceParams, string(object.Driver))
	deviceParams = append(deviceParams, fmt.Sprintf(",id=%s", object.DeviceID))

	switch object.Type {
	case MemoryBackendFile:
		objectParams = append(objectParams, string(object.Type))
		objectParams = append(objectParams, fmt.Sprintf(",id=%s", object.ID))
		objectParams = append(objectParams, fmt.Sprintf(",mem-path=%s", object.MemPath))
		objectParams = append(objectParams, fmt.Sprintf(",size=%d", object.Size))

		deviceParams = append(deviceParams, fmt.Sprintf(",memdev=%s", object.ID))
	}

	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ""))

	qemuParams = append(qemuParams, "-object")
	qemuParams = append(qemuParams, strings.Join(objectParams, ""))

	return qemuParams
}

type FSDriver string

type SecurityModelType string

const (
	Local  FSDriver = "local"
	Handle FSDriver = "handle"
	Proxy  FSDriver = "proxy"
)

const (
	None        SecurityModelType = "none"
	PassThrough SecurityModelType = "passthrough"
	MappedXattr SecurityModelType = "mapped-xattr"
	MappedFile  SecurityModelType = "mapped-file"
)

type FSDevice struct {
	Driver        DeviceDriver
	FSDriver      FSDriver
	ID            string
	Path          string
	MountTag      string
	SecurityModel SecurityModelType
	DisableModern bool
	ROMFile       string
}

func (fsdev FSDevice) Valid() bool {
	if fsdev.ID == "" || fsdev.Path == "" || fsdev.MountTag == "" {
		return false
	}

	return true
}

func (fsdev FSDevice) QemuParams(config *Config) []string {
	var fsParams []string
	var deviceParams []string
	var qemuParams []string

	deviceParams = append(deviceParams, fmt.Sprintf("%s", fsdev.Driver))
	if fsdev.DisableModern {
		deviceParams = append(deviceParams, ",disable-modern=true")
	}
	deviceParams = append(deviceParams, fmt.Sprintf(",fsdev=%s", fsdev.ID))
	deviceParams = append(deviceParams, fmt.Sprintf(",mount_tag=%s", fsdev.MountTag))
	if isVirtioPCI[fsdev.Driver] {
		deviceParams = append(deviceParams, fmt.Sprintf(",romfile=%s", fsdev.ROMFile))
	}

	fsParams = append(fsParams, string(fsdev.FSDriver))
	fsParams = append(fsParams, fmt.Sprintf(",id=%s", fsdev.ID))
	fsParams = append(fsParams, fmt.Sprintf(",path=%s", fsdev.Path))
	fsParams = append(fsParams, fmt.Sprintf(",security_model=%s", fsdev.SecurityModel))

	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ""))

	qemuParams = append(qemuParams, "-fsdev")
	qemuParams = append(qemuParams, strings.Join(fsParams, ""))

	return qemuParams
}

type CharDeviceBackend string

const (
	Pipe        CharDeviceBackend = "pipe"
	Socket      CharDeviceBackend = "socket"
	CharConsole CharDeviceBackend = "console"
	Serial      CharDeviceBackend = "serial"
	TTY         CharDeviceBackend = "tty"
	PTY         CharDeviceBackend = "pty"
)

type CharDevice struct {
	Backend       CharDeviceBackend
	Driver        DeviceDriver
	Bus           string
	DeviceID      string
	ID            string
	Path          string
	Name          string
	DisableModern bool
	ROMFile       string
}

func (cdev CharDevice) Valid() bool {
	if cdev.ID == "" || cdev.Path == "" {
		return false
	}

	return true
}

func (cdev CharDevice) QemuParams(config *Config) []string {
	var cdevParams []string
	var deviceParams []string
	var qemuParams []string

	deviceParams = append(deviceParams, fmt.Sprintf("%s", cdev.Driver))
	if cdev.DisableModern {
		deviceParams = append(deviceParams, ",disable-modern=true")
	}
	if cdev.Bus != "" {
		deviceParams = append(deviceParams, fmt.Sprintf(",bus=%s", cdev.Bus))
	}
	deviceParams = append(deviceParams, fmt.Sprintf(",chardev=%s", cdev.ID))
	deviceParams = append(deviceParams, fmt.Sprintf(",id=%s", cdev.DeviceID))
	if cdev.Name != "" {
		deviceParams = append(deviceParams, fmt.Sprintf(",name=%s", cdev.Name))
	}
	if isVirtioPCI[cdev.Driver] {
		deviceParams = append(deviceParams, fmt.Sprintf(",romfile=%s", cdev.ROMFile))
	}

	cdevParams = append(cdevParams, string(cdev.Backend))
	cdevParams = append(cdevParams, fmt.Sprintf(",id=%s", cdev.ID))
	if cdev.Backend == Socket {
		cdevParams = append(cdevParams, fmt.Sprintf(",path=%s,server,nowait", cdev.Path))
	} else {
		cdevParams = append(cdevParams, fmt.Sprintf(",path=%s", cdev.Path))
	}

	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ""))

	qemuParams = append(qemuParams, "-chardev")
	qemuParams = append(qemuParams, strings.Join(cdevParams, ""))

	return qemuParams
}

type NetDeviceType string

const (
	TAP       NetDeviceType = "tap"
	MACVTAP   NetDeviceType = "macvtap"
	IPVTAP    NetDeviceType = "ipvtap"
	VETHTAP   NetDeviceType = "vethtap"
	VFIO      NetDeviceType = "VFIO"
	VHOSTUSER NetDeviceType = "vhostuser"
)

func (n NetDeviceType) QemuNetdevParam() string {
	switch n {
	case TAP:
		return "tap"
	case MACVTAP:
		return "tap"
	case IPVTAP:
		return "tap"
	case VETHTAP:
		return "tap" // -netdev type=tap -device virtio-net-pci
	case VFIO:
		return "" // -device vfio-pci (no netdev)
	case VHOSTUSER:
		return "vhost-user" // -netdev type=vhost-user (no device)
	default:
		return ""

	}
}

func (n NetDeviceType) QemuDeviceParam() DeviceDriver {
	switch n {
	case TAP:
		return "virtio-net-pci"
	case MACVTAP:
		return "virtio-net-pci"
	case IPVTAP:
		return "virtio-net-pci"
	case VETHTAP:
		return "virtio-net-pci" // -netdev type=tap -device virtio-net-pci
	case VFIO:
		return "vfio-pci" // -device vfio-pci (no netdev)
	case VHOSTUSER:
		return "" // -netdev type=vhost-user (no device)
	default:
		return ""

	}
}

type NetDevice struct {
	Type          NetDeviceType
	Driver        DeviceDriver
	ID            string // ID is the netdevice identifier.
	IFName        string
	Bus           string     // Bus is the bus path name of a PCI device.
	Addr          string     // Addr is the address offset of a PCI device.
	DownScript    string     // DownScript is the tap interface deconfiguration script.
	Script        string     // Script is the tap interface configuration script.
	FDs           []*os.File // FDs represents the list of already existing file descriptors to be used.
	VhostFDs      []*os.File
	VHost         bool   // VHost enables virtio device emulation from the host kernel instead of from qemu.
	MACAddress    string // MACAddress is the networking device interface MAC address.
	DisableModern bool   // DisableModern prevents qemu from relying on fast MMIO.
	ROMFile       string // ROMFile specifies the ROM file being used for this device.
}

func (netdev NetDevice) Valid() bool {
	if netdev.ID == "" || netdev.IFName == "" {
		return false
	}

	switch netdev.Type {
	case TAP:
		return true
	case MACVTAP:
		return true
	default:
		return false
	}
}

func (netdev NetDevice) QemuDeviceParams(config *Config) []string {
	var deviceParams []string

	if netdev.Type.QemuDeviceParam() == "" {
		return nil
	}

	deviceParams = append(deviceParams, fmt.Sprintf("driver=%s", netdev.Type.QemuDeviceParam()))
	deviceParams = append(deviceParams, fmt.Sprintf(",netdev=%s", netdev.ID))
	deviceParams = append(deviceParams, fmt.Sprintf(",mac=%s", netdev.MACAddress))

	if netdev.Bus != "" {
		deviceParams = append(deviceParams, fmt.Sprintf(",bus=%s", netdev.Bus))
	}

	if netdev.Addr != "" {
		addr, err := strconv.Atoi(netdev.Addr)
		if err == nil && addr >= 0 {
			deviceParams = append(deviceParams, fmt.Sprintf(",addr=%x", addr))
		}
	}

	if netdev.DisableModern {
		deviceParams = append(deviceParams, ",disable-modern=true")
	}

	if len(netdev.FDs) > 0 {
		// https://www.linux-kvm.org/page/Multiqueue
		// -netdev tap,vhost=on,queues=N
		// enable mq and specify msix vectors in qemu cmdline
		// (2N+2 vectors, N for tx queues, N for rx queues, 1 for config, and one for possible control vq)
		// -device virtio-net-pci,mq=on,vectors=2N+2...
		// enable mq in guest by 'ethtool -L eth0 combined $queue_num'
		// Clearlinux automatically sets up the queues properly
		// The agent implementation should do this to ensure that it is
		// always set
		vectors := len(netdev.FDs)*2 + 2

		// Note: We are appending to the device params here
		deviceParams = append(deviceParams, ",mq=on")
		deviceParams = append(deviceParams, fmt.Sprintf(",vectors=%d", vectors))
	}

	if isVirtioPCI[netdev.Driver] {
		deviceParams = append(deviceParams, fmt.Sprintf(",romfile=%s", netdev.ROMFile))
	}

	return deviceParams
}

// QemuNetdevParams returns the -netdev parameters for this network device
func (netdev NetDevice) QemuNetdevParams(config *Config) []string {
	var netdevParams []string

	if netdev.Type.QemuNetdevParam() == "" {
		return nil
	}

	netdevParams = append(netdevParams, netdev.Type.QemuNetdevParam())
	netdevParams = append(netdevParams, fmt.Sprintf(",id=%s", netdev.ID))

	if netdev.VHost == true {
		netdevParams = append(netdevParams, ",vhost=on")
		if len(netdev.VhostFDs) > 0 {
			var fdParams []string
			qemuFDs := config.appendFDs(netdev.VhostFDs)
			for _, fd := range qemuFDs {
				fdParams = append(fdParams, fmt.Sprintf("%d", fd))
			}
			netdevParams = append(netdevParams, fmt.Sprintf(",vhostfds=%s", strings.Join(fdParams, ":")))
		}
	}

	if len(netdev.FDs) > 0 {
		var fdParams []string

		qemuFDs := config.appendFDs(netdev.FDs)
		for _, fd := range qemuFDs {
			fdParams = append(fdParams, fmt.Sprintf("%d", fd))
		}

		netdevParams = append(netdevParams, fmt.Sprintf(",fds=%s", strings.Join(fdParams, ":")))

	} else {
		netdevParams = append(netdevParams, fmt.Sprintf(",ifname=%s", netdev.IFName))
		if netdev.DownScript != "" {
			netdevParams = append(netdevParams, fmt.Sprintf(",downscript=%s", netdev.DownScript))
		}
		if netdev.Script != "" {
			netdevParams = append(netdevParams, fmt.Sprintf(",script=%s", netdev.Script))
		}
	}
	return netdevParams
}

// QemuParams returns the qemu parameters built out of this network device.
func (netdev NetDevice) QemuParams(config *Config) []string {
	var netdevParams []string
	var deviceParams []string
	var qemuParams []string

	// Macvtap can only be connected via fds
	if (netdev.Type == MACVTAP) && (len(netdev.FDs) == 0) {
		return nil // implicit error
	}

	if netdev.Type.QemuNetdevParam() != "" {
		netdevParams = netdev.QemuNetdevParams(config)
		if netdevParams != nil {
			qemuParams = append(qemuParams, "-netdev")
			qemuParams = append(qemuParams, strings.Join(netdevParams, ""))
		}
	}

	if netdev.Type.QemuDeviceParam() != "" {
		deviceParams = netdev.QemuDeviceParams(config)
		if deviceParams != nil {
			qemuParams = append(qemuParams, "-device")
			qemuParams = append(qemuParams, strings.Join(deviceParams, ""))
		}
	}

	return qemuParams
}

type SerialDevice struct {
	Driver        DeviceDriver // Driver is the qemu device driver
	ID            string       // ID is the serial device identifier.
	DisableModern bool         // DisableModern prevents qemu from relying on fast MMIO.
	ROMFile       string       // ROMFile specifies the ROM file being used for this device.
}

func (dev SerialDevice) Valid() bool {
	if dev.Driver == "" || dev.ID == "" {
		return false
	}

	return true
}

func (dev SerialDevice) QemuParams(config *Config) []string {
	var deviceParams []string
	var qemuParams []string

	deviceParams = append(deviceParams, fmt.Sprintf("%s", dev.Driver))
	if dev.DisableModern {
		deviceParams = append(deviceParams, ",disable-modern=true")
	}
	deviceParams = append(deviceParams, fmt.Sprintf(",id=%s", dev.ID))
	if isVirtioPCI[dev.Driver] {
		deviceParams = append(deviceParams, fmt.Sprintf(",romfile=%s", dev.ROMFile))
	}

	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ""))

	return qemuParams
}

type BlockDeviceInterface string

type BlockDeviceAIO string

type BlockDeviceFormat string

const (
	NoInterface BlockDeviceInterface = "none"
	SCSI        BlockDeviceInterface = "scsi"
)

const (
	Threads BlockDeviceAIO = "threads"
	Native  BlockDeviceAIO = "native"
)

const (
	QCOW2 BlockDeviceFormat = "qcow2"
)

type BlockDevice struct {
	Driver        DeviceDriver
	ID            string
	File          string
	Interface     BlockDeviceInterface
	AIO           BlockDeviceAIO
	Format        BlockDeviceFormat
	SCSI          bool
	WCE           bool
	DisableModern bool   // DisableModern prevents qemu from relying on fast MMIO.
	ROMFile       string // ROMFile specifies the ROM file being used for this device.
}

func (blkdev BlockDevice) Valid() bool {
	if blkdev.Driver == "" || blkdev.ID == "" || blkdev.File == "" {
		return false
	}

	return true
}

func (blkdev BlockDevice) QemuParams(config *Config) []string {
	var blkParams []string
	var deviceParams []string
	var qemuParams []string

	deviceParams = append(deviceParams, fmt.Sprintf("%s", blkdev.Driver))
	if blkdev.DisableModern {
		deviceParams = append(deviceParams, ",disable-modern=true")
	}
	deviceParams = append(deviceParams, fmt.Sprintf(",drive=%s", blkdev.ID))
	if blkdev.SCSI == false {
		deviceParams = append(deviceParams, ",scsi=off")
	}

	if blkdev.WCE == false {
		deviceParams = append(deviceParams, ",config-wce=off")
	}

	if isVirtioPCI[blkdev.Driver] {
		deviceParams = append(deviceParams, fmt.Sprintf(",romfile=%s", blkdev.ROMFile))
	}

	blkParams = append(blkParams, fmt.Sprintf("id=%s", blkdev.ID))
	blkParams = append(blkParams, fmt.Sprintf(",file=%s", blkdev.File))
	blkParams = append(blkParams, fmt.Sprintf(",aio=%s", blkdev.AIO))
	blkParams = append(blkParams, fmt.Sprintf(",format=%s", blkdev.Format))
	blkParams = append(blkParams, fmt.Sprintf(",if=%s", blkdev.Interface))

	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ""))

	qemuParams = append(qemuParams, "-drive")
	qemuParams = append(qemuParams, strings.Join(blkParams, ""))

	return qemuParams
}

type VhostUserDevice struct {
	SocketPath    string //path to vhostuser socket on host
	CharDevID     string
	TypeDevID     string //variable QEMU parameter based on value of VhostUserType
	Address       string //used for MAC address in net case
	VhostUserType DeviceDriver
	ROMFile       string // ROMFile specifies the ROM file being used for this device.
}

// Valid returns true if there is a valid structure defined for VhostUserDevice
func (vhostuserDev VhostUserDevice) Valid() bool {

	if vhostuserDev.SocketPath == "" || vhostuserDev.CharDevID == "" {
		return false
	}

	switch vhostuserDev.VhostUserType {
	case VhostUserNet:
		if vhostuserDev.TypeDevID == "" || vhostuserDev.Address == "" {
			return false
		}
	case VhostUserSCSI:
		if vhostuserDev.TypeDevID == "" {
			return false
		}
	case VhostUserBlk:
	default:
		return false
	}

	return true
}

// QemuParams returns the qemu parameters built out of this vhostuser device.
func (vhostuserDev VhostUserDevice) QemuParams(config *Config) []string {
	var qemuParams []string
	var charParams []string
	var netParams []string
	var devParams []string
	var driver DeviceDriver

	charParams = append(charParams, "socket")
	charParams = append(charParams, fmt.Sprintf("id=%s", vhostuserDev.CharDevID))
	charParams = append(charParams, fmt.Sprintf("path=%s", vhostuserDev.SocketPath))

	switch vhostuserDev.VhostUserType {
	// if network based vhost device:
	case VhostUserNet:
		driver = VhostUserNet
		netParams = append(netParams, "type=vhost-user")
		netParams = append(netParams, fmt.Sprintf("id=%s", vhostuserDev.TypeDevID))
		netParams = append(netParams, fmt.Sprintf("chardev=%s", vhostuserDev.CharDevID))
		netParams = append(netParams, "vhostforce")

		devParams = append(devParams, string(driver))
		devParams = append(devParams, fmt.Sprintf("netdev=%s", vhostuserDev.TypeDevID))
		devParams = append(devParams, fmt.Sprintf("mac=%s", vhostuserDev.Address))
	case VhostUserSCSI:
		driver = VhostUserSCSI
		devParams = append(devParams, string(driver))
		devParams = append(devParams, fmt.Sprintf("id=%s", vhostuserDev.TypeDevID))
		devParams = append(devParams, fmt.Sprintf("chardev=%s", vhostuserDev.CharDevID))
	case VhostUserBlk:
		driver = VhostUserBlk
		devParams = append(devParams, string(driver))
		devParams = append(devParams, "logical_block_size=4096")
		devParams = append(devParams, "size=512M")
		devParams = append(devParams, fmt.Sprintf("chardev=%s", vhostuserDev.CharDevID))
	default:
		return nil
	}

	if isVirtioPCI[driver] {
		devParams = append(devParams, fmt.Sprintf("romfile=%s", vhostuserDev.ROMFile))
	}

	qemuParams = append(qemuParams, "-chardev")
	qemuParams = append(qemuParams, strings.Join(charParams, ","))

	// if network based vhost device:
	if vhostuserDev.VhostUserType == VhostUserNet {
		qemuParams = append(qemuParams, "-netdev")
		qemuParams = append(qemuParams, strings.Join(netParams, ","))
	}
	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(devParams, ","))

	return qemuParams
}

type VFIODevice struct {
	BDF     string // Bus-Device-Function of device
	ROMFile string // ROMFile specifies the ROM file being used for this device.
}

func (vfioDev VFIODevice) Valid() bool {
	if vfioDev.BDF == "" {
		return false
	}

	return true
}

func (vfioDev VFIODevice) QemuParams(config *Config) []string {
	var qemuParams []string
	var deviceParams []string
	driver := VfioPCI
	deviceParams = append(deviceParams, fmt.Sprintf("%s,host=%s", driver, vfioDev.BDF))
	if isVirtioPCI[driver] {
		deviceParams = append(deviceParams, fmt.Sprintf(",romfile=%s", vfioDev.ROMFile))
	}
	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ""))
	return qemuParams
}

type SCSIController struct {
	ID            string
	Bus           string // Bus on which the SCSI controller is attached, this is optional
	Addr          string
	DisableModern bool // DisableModern prevents qemu from relying on fast MMIO.
	IOThread      string
	ROMFile       string // ROMFile specifies the ROM file being used for this device.
}

func (scsiCon SCSIController) Valid() bool {
	if scsiCon.ID == "" {
		return false
	}

	return true
}

func (scsiCon SCSIController) QemuParams(config *Config) []string {
	var qemuParams []string
	var devParams []string

	driver := VirtioScsiPCI
	devParams = append(devParams, fmt.Sprintf("%s,id=%s", driver, scsiCon.ID))
	if scsiCon.Bus != "" {
		devParams = append(devParams, fmt.Sprintf("bus=%s", scsiCon.Bus))
	}
	if scsiCon.Addr != "" {
		devParams = append(devParams, fmt.Sprintf("addr=%s", scsiCon.Addr))
	}
	if scsiCon.DisableModern {
		devParams = append(devParams, fmt.Sprintf("disable-modern=true"))
	}
	if scsiCon.IOThread != "" {
		devParams = append(devParams, fmt.Sprintf("iothread=%s", scsiCon.IOThread))
	}
	if isVirtioPCI[driver] {
		devParams = append(devParams, fmt.Sprintf("romfile=%s", scsiCon.ROMFile))
	}
	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(devParams, ","))
	return qemuParams
}

type BridgeType uint

const (
	PCIBridge BridgeType = iota
	PCIEBridge
)

type BridgeDevice struct {
	Type    BridgeType
	Bus     string // Bus number where the bridge is plugged, typically pci.0 or pcie.0
	ID      string // ID is used to identify the bridge in qemu
	Chassis int    // Chassis number
	SHPC    bool   // SHPC is used to enable or disable the standard hot plug controller
	Addr    string
	ROMFile string // ROMFile specifies the ROM file being used for this device.
}

func (bridgeDev BridgeDevice) Valid() bool {
	if bridgeDev.Type != PCIBridge && bridgeDev.Type != PCIEBridge {
		return false
	}

	if bridgeDev.Bus == "" {
		return false
	}

	if bridgeDev.ID == "" {
		return false
	}

	return true
}

func (bridgeDev BridgeDevice) QemuParams(config *Config) []string {
	var qemuParams []string
	var deviceParam []string
	var driver DeviceDriver

	switch bridgeDev.Type {
	case PCIEBridge:
		driver = PCIePCIBridgeDriver
		deviceParam = append(deviceParam, fmt.Sprintf("%s,bus=%s,id=%s", driver, bridgeDev.Bus, bridgeDev.ID))
	default:
		driver = PCIBridgeDriver
		shpc := "off"
		if bridgeDev.SHPC {
			shpc = "on"
		}
		deviceParam = append(deviceParam, fmt.Sprintf("%s,bus=%s,id=%s,chassis_nr=%d,shpc=%s", driver, bridgeDev.Bus, bridgeDev.ID, bridgeDev.Chassis, shpc))
	}
	if bridgeDev.Addr != "" {
		addr, err := strconv.Atoi(bridgeDev.Addr)
		if err == nil && addr >= 0 {
			deviceParam = append(deviceParam, fmt.Sprintf(",addr=%x", addr))
		}
	}
	if isVirtioPCI[driver] {
		deviceParam = append(deviceParam, fmt.Sprintf(",romfile=%s", bridgeDev.ROMFile))
	}
	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParam, ""))
	return qemuParams
}

type VSOCKDevice struct {
	ID            string
	ContextID     uint32
	VHostFD       *os.File
	DisableModern bool
	ROMFile       string
}

const (
	MinimalGuestCID uint32 = 3
	VSOCKGuestCID          = "guest-cid"
)

func (vsock VSOCKDevice) Valid() bool {
	if vsock.ID == "" || vsock.ContextID < MinimalGuestCID {
		return false
	}
	return true
}

func (vsock VSOCKDevice) QemuParams(config *Config) []string {
	var deviceParams []string
	var qemuParams []string
	driver := VHostVSockPCI
	deviceParams = append(deviceParams, fmt.Sprintf("%s", driver))
	if vsock.DisableModern {
		deviceParams = append(deviceParams, ",disable-modern=true")
	}
	if vsock.VHostFD != nil {
		qemuFDs := config.appendFDs([]*os.File{vsock.VHostFD})
		deviceParams = append(deviceParams, fmt.Sprintf(",vhostfd=%d", qemuFDs[0]))
	}
	deviceParams = append(deviceParams, fmt.Sprintf(",id=%s", vsock.ID))
	deviceParams = append(deviceParams, fmt.Sprintf(",%s=%d", VSOCKGuestCID, vsock.ContextID))
	if isVirtioPCI[driver] {
		deviceParams = append(deviceParams, fmt.Sprintf(",romfile=%s", vsock.ROMFile))
	}
	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ""))
	return qemuParams
}

type RngDevice struct {
	ID       string
	Filename string // Filename is entropy source on the host
	MaxBytes uint   // MaxBytes is the bytes allowed to guest to get from the host’s entropy per period
	Period   uint   // Period is duration of a read period in seconds
	ROMFile  string
}

func (v RngDevice) Valid() bool {
	if v.ID == "" {
		return false
	}
	return true
}

func (v RngDevice) QemuParams(_ *Config) []string {
	var qemuParams []string
	var objectParams []string
	var deviceParams []string

	driver := VirtioRng
	objectParams = append(objectParams, "rng-random")
	objectParams = append(objectParams, "id="+v.ID)

	deviceParams = append(deviceParams, string(driver))
	deviceParams = append(deviceParams, "rng="+v.ID)

	if isVirtioPCI[driver] {
		deviceParams = append(deviceParams, fmt.Sprintf("romfile=%s", v.ROMFile))
	}

	if v.Filename != "" {
		objectParams = append(objectParams, "filename="+v.Filename)
	}

	if v.MaxBytes > 0 {
		deviceParams = append(deviceParams, fmt.Sprintf("max-bytes=%d", v.MaxBytes))
	}

	if v.Period > 0 {
		deviceParams = append(deviceParams, fmt.Sprintf("period=%d", v.Period))
	}

	qemuParams = append(qemuParams, "-object")
	qemuParams = append(qemuParams, strings.Join(objectParams, ","))

	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ","))

	return qemuParams
}

type BalloonDevice struct {
	DeflateOnOOM  bool
	DisableModern bool
	ID            string

	ROMFile string
}

func (b BalloonDevice) QemuParams(_ *Config) []string {
	var qemuParams []string
	var deviceParams []string

	driver := VirtioBalloon
	deviceParams = append(deviceParams, string(driver))

	if b.ID != "" {
		deviceParams = append(deviceParams, "id="+b.ID)
	}

	if isVirtioPCI[driver] {
		deviceParams = append(deviceParams, fmt.Sprintf("romfile=%s", b.ROMFile))
	}

	if b.DeflateOnOOM {
		deviceParams = append(deviceParams, "deflate-on-oom=on")
	} else {
		deviceParams = append(deviceParams, "deflate-on-oom=off")
	}

	if b.DisableModern {
		deviceParams = append(deviceParams, "disable-modern=on")
	} else {
		deviceParams = append(deviceParams, "disable-modern=off")
	}

	qemuParams = append(qemuParams, "-device")
	qemuParams = append(qemuParams, strings.Join(deviceParams, ","))

	return qemuParams
}

func (b BalloonDevice) Valid() bool {
	if b.ID == "" {
		return false
	}
	return true
}

type RTCBaseType string

type RTCClock string

type RTCDriftFix string

const (
	UTC       RTCBaseType = "utc"
	LocalTime RTCBaseType = "localtime"
)

const (
	Host RTCClock = "host"
	VM   RTCClock = "vm"
)

const (
	Slew       RTCDriftFix = "slew"
	NoDriftFix RTCDriftFix = "none"
)

type RTC struct {
	Base     RTCBaseType
	Clock    RTCClock
	DriftFix RTCDriftFix
}

func (rtc RTC) Valid() bool {
	if rtc.Clock != Host && rtc.Clock != VM {
		return false
	}
	if rtc.DriftFix != Slew && rtc.DriftFix != NoDriftFix {
		return false
	}
	return true
}

type QMPSocketType string

const (
	Unix QMPSocketType = "unix"
)

type QMPSocket struct {
	Type   QMPSocketType
	Name   string
	Server bool
	NoWait bool
}

func (qmp QMPSocket) Valid() bool {
	if qmp.Type == "" || qmp.Name == "" {
		return false
	}
	if qmp.Type != Unix {
		return false
	}
	return true
}

type SMP struct {
	CPUs    uint32
	Cores   uint32
	Threads uint32
	Sockets uint32
	MaxCPUs uint32
}

type Memory struct {
	Size   string
	Slots  uint8
	MaxMem string
	Path   string
}

type Kernel struct {
	Path       string
	InitrdPath string
	Params     string
}

type Knobs struct {
	NoUserConfig        bool
	NoDefaults          bool
	NoGraphic           bool
	Daemonize           bool
	HugePages           bool
	MemPrealloc         bool
	FileBackedMem       bool
	FileBackedMemShared bool
	Mlock               bool
	Stopped             bool
	Realtime            bool
}

type IOThread struct {
	ID string
}

const (
	MigrationFD   = 1
	MigrationExec = 2
)

type Incoming struct {
	MigrationType int
	FD            *os.File
	Exec          string
}

type Config struct {
	Path        string
	Ctx         context.Context
	Name        string
	UUID        string
	CPUModel    string
	Machine     Machine
	QMPSockets  []QMPSocket
	Devices     []Device
	RTC         RTC
	VGA         string
	Kernel      Kernel
	Memory      Memory
	SMP         SMP
	GlobalParam string
	Knobs       Knobs
	Bios        string
	Incoming    Incoming
	fds         []*os.File
	IOThreads   []IOThread
	qemuParams  []string
}

func (config *Config) appendFDs(fds []*os.File) []int {
	var fdInts []int

	oldLen := len(config.fds)

	config.fds = append(config.fds, fds...)

	// The magic 3 offset comes from https://golang.org/src/os/exec/exec.go:
	//     ExtraFiles specifies additional open files to be inherited by the
	//     new process. It does not include standard input, standard output, or
	//     standard error. If non-nil, entry i becomes file descriptor 3+i.
	for i := range fds {
		fdInts = append(fdInts, oldLen+3+i)
	}

	return fdInts
}

func (config *Config) appendName() {
	if config.Name != "" {
		config.qemuParams = append(config.qemuParams, "-name")
		config.qemuParams = append(config.qemuParams, config.Name)
	}
}

func (config *Config) appendMachine() {
	if config.Machine.Type != "" {
		var machineParams []string

		machineParams = append(machineParams, config.Machine.Type)

		if config.Machine.Acceleration != "" {
			machineParams = append(machineParams, fmt.Sprintf(",accel=%s", config.Machine.Acceleration))
		}

		if config.Machine.Options != "" {
			machineParams = append(machineParams, fmt.Sprintf(",%s", config.Machine.Options))
		}

		config.qemuParams = append(config.qemuParams, "-machine")
		config.qemuParams = append(config.qemuParams, strings.Join(machineParams, ""))
	}
}

func (config *Config) appendCPUModel() {
	if config.CPUModel != "" {
		config.qemuParams = append(config.qemuParams, "-cpu")
		config.qemuParams = append(config.qemuParams, config.CPUModel)
	}
}

func (config *Config) appendQMPSockets() {
	for _, q := range config.QMPSockets {
		if q.Valid() == false {
			continue
		}

		qmpParams := append([]string{}, fmt.Sprintf("%s:", q.Type))
		qmpParams = append(qmpParams, fmt.Sprintf("%s", q.Name))
		if q.Server == true {
			qmpParams = append(qmpParams, ",server")
			if q.NoWait == true {
				qmpParams = append(qmpParams, ",nowait")
			}
		}

		config.qemuParams = append(config.qemuParams, "-qmp")
		config.qemuParams = append(config.qemuParams, strings.Join(qmpParams, ""))
	}
}

func (config *Config) appendDevices() {
	for _, d := range config.Devices {
		if d.Valid() == false {
			continue
		}

		config.qemuParams = append(config.qemuParams, d.QemuParams(config)...)
	}
}

func (config *Config) appendUUID() {
	if config.UUID != "" {
		config.qemuParams = append(config.qemuParams, "-uuid")
		config.qemuParams = append(config.qemuParams, config.UUID)
	}
}

func (config *Config) appendMemory() {
	if config.Memory.Size != "" {
		var memoryParams []string

		memoryParams = append(memoryParams, config.Memory.Size)

		if config.Memory.Slots > 0 {
			memoryParams = append(memoryParams, fmt.Sprintf(",slots=%d", config.Memory.Slots))
		}

		if config.Memory.MaxMem != "" {
			memoryParams = append(memoryParams, fmt.Sprintf(",maxmem=%s", config.Memory.MaxMem))
		}

		config.qemuParams = append(config.qemuParams, "-m")
		config.qemuParams = append(config.qemuParams, strings.Join(memoryParams, ""))
	}
}

func (config *Config) appendCPUs() error {
	if config.SMP.CPUs > 0 {
		var SMPParams []string

		SMPParams = append(SMPParams, fmt.Sprintf("%d", config.SMP.CPUs))

		if config.SMP.Cores > 0 {
			SMPParams = append(SMPParams, fmt.Sprintf(",cores=%d", config.SMP.Cores))
		}

		if config.SMP.Threads > 0 {
			SMPParams = append(SMPParams, fmt.Sprintf(",threads=%d", config.SMP.Threads))
		}

		if config.SMP.Sockets > 0 {
			SMPParams = append(SMPParams, fmt.Sprintf(",sockets=%d", config.SMP.Sockets))
		}

		if config.SMP.MaxCPUs > 0 {
			if config.SMP.MaxCPUs < config.SMP.CPUs {
				return fmt.Errorf("MaxCPUs %d must be equal to or greater than CPUs %d",
					config.SMP.MaxCPUs, config.SMP.CPUs)
			}
			SMPParams = append(SMPParams, fmt.Sprintf(",maxcpus=%d", config.SMP.MaxCPUs))
		}

		config.qemuParams = append(config.qemuParams, "-smp")
		config.qemuParams = append(config.qemuParams, strings.Join(SMPParams, ""))
	}

	return nil
}

func (config *Config) appendRTC() {
	if config.RTC.Valid() == false {
		return
	}

	var RTCParams []string

	RTCParams = append(RTCParams, fmt.Sprintf("base=%s", string(config.RTC.Base)))

	if config.RTC.DriftFix != "" {
		RTCParams = append(RTCParams, fmt.Sprintf(",driftfix=%s", config.RTC.DriftFix))
	}

	if config.RTC.Clock != "" {
		RTCParams = append(RTCParams, fmt.Sprintf(",clock=%s", config.RTC.Clock))
	}

	config.qemuParams = append(config.qemuParams, "-rtc")
	config.qemuParams = append(config.qemuParams, strings.Join(RTCParams, ""))
}

func (config *Config) appendGlobalParam() {
	if config.GlobalParam != "" {
		config.qemuParams = append(config.qemuParams, "-global")
		config.qemuParams = append(config.qemuParams, config.GlobalParam)
	}
}

func (config *Config) appendVGA() {
	if config.VGA != "" {
		config.qemuParams = append(config.qemuParams, "-vga")
		config.qemuParams = append(config.qemuParams, config.VGA)
	}
}

func (config *Config) appendKernel() {
	if config.Kernel.Path != "" {
		config.qemuParams = append(config.qemuParams, "-kernel")
		config.qemuParams = append(config.qemuParams, config.Kernel.Path)

		if config.Kernel.InitrdPath != "" {
			config.qemuParams = append(config.qemuParams, "-initrd")
			config.qemuParams = append(config.qemuParams, config.Kernel.InitrdPath)
		}

		if config.Kernel.Params != "" {
			config.qemuParams = append(config.qemuParams, "-append")
			config.qemuParams = append(config.qemuParams, config.Kernel.Params)
		}
	}
}

func (config *Config) appendMemoryKnobs() {
	if config.Knobs.HugePages == true {
		if config.Memory.Size != "" {
			dimmName := "dimm1"
			objMemParam := "memory-backend-file,id=" + dimmName + ",size=" + config.Memory.Size + ",mem-path=/dev/hugepages,share=on,prealloc=on"
			numaMemParam := "node,memdev=" + dimmName

			config.qemuParams = append(config.qemuParams, "-object")
			config.qemuParams = append(config.qemuParams, objMemParam)

			config.qemuParams = append(config.qemuParams, "-numa")
			config.qemuParams = append(config.qemuParams, numaMemParam)
		}
	} else if config.Knobs.MemPrealloc == true {
		if config.Memory.Size != "" {
			dimmName := "dimm1"
			objMemParam := "memory-backend-ram,id=" + dimmName + ",size=" + config.Memory.Size + ",prealloc=on"
			numaMemParam := "node,memdev=" + dimmName

			config.qemuParams = append(config.qemuParams, "-object")
			config.qemuParams = append(config.qemuParams, objMemParam)

			config.qemuParams = append(config.qemuParams, "-numa")
			config.qemuParams = append(config.qemuParams, numaMemParam)
		}
	} else if config.Knobs.FileBackedMem == true {
		if config.Memory.Size != "" && config.Memory.Path != "" {
			dimmName := "dimm1"
			objMemParam := "memory-backend-file,id=" + dimmName + ",size=" + config.Memory.Size + ",mem-path=" + config.Memory.Path
			if config.Knobs.FileBackedMemShared == true {
				objMemParam += ",share=on"
			}
			numaMemParam := "node,memdev=" + dimmName

			config.qemuParams = append(config.qemuParams, "-object")
			config.qemuParams = append(config.qemuParams, objMemParam)

			config.qemuParams = append(config.qemuParams, "-numa")
			config.qemuParams = append(config.qemuParams, numaMemParam)
		}
	}
}

func (config *Config) appendKnobs() {
	if config.Knobs.NoUserConfig == true {
		config.qemuParams = append(config.qemuParams, "-no-user-config")
	}

	if config.Knobs.NoDefaults == true {
		config.qemuParams = append(config.qemuParams, "-nodefaults")
	}

	if config.Knobs.NoGraphic == true {
		config.qemuParams = append(config.qemuParams, "-nographic")
	}

	if config.Knobs.Daemonize == true {
		config.qemuParams = append(config.qemuParams, "-daemonize")
	}

	config.appendMemoryKnobs()

	if config.Knobs.Realtime == true {
		config.qemuParams = append(config.qemuParams, "-realtime")
		// This path is redundant as the default behaviour is locked memory
		// Realtime today does not control any other feature even though
		// other features may be added in the future
		// https://lists.gnu.org/archive/html/qemu-devel/2012-12/msg03330.html
		if config.Knobs.Mlock == true {
			config.qemuParams = append(config.qemuParams, "mlock=on")
		} else {
			config.qemuParams = append(config.qemuParams, "mlock=off")
		}
	} else {
		if config.Knobs.Mlock == false {
			config.qemuParams = append(config.qemuParams, "-realtime")
			config.qemuParams = append(config.qemuParams, "mlock=off")
		}
	}

	if config.Knobs.Stopped == true {
		config.qemuParams = append(config.qemuParams, "-S")
	}
}

func (config *Config) appendBios() {
	if config.Bios != "" {
		config.qemuParams = append(config.qemuParams, "-bios")
		config.qemuParams = append(config.qemuParams, config.Bios)
	}
}

func (config *Config) appendIOThreads() {
	for _, t := range config.IOThreads {
		if t.ID != "" {
			config.qemuParams = append(config.qemuParams, "-object")
			config.qemuParams = append(config.qemuParams, fmt.Sprintf("iothread,id=%s", t.ID))
		}
	}
}

func (config *Config) appendIncoming() {
	var uri string
	switch config.Incoming.MigrationType {
	case MigrationExec:
		uri = fmt.Sprintf("exec:%s", config.Incoming.Exec)
	case MigrationFD:
		chFDs := config.appendFDs([]*os.File{config.Incoming.FD})
		uri = fmt.Sprintf("fd:%d", chFDs[0])
	default:
		return
	}
	config.qemuParams = append(config.qemuParams, "-S", "-incoming", uri)
}

func LaunchQemu(config Config, logger QMPLog) (string, error) {
	config.appendName()
	config.appendUUID()
	config.appendMachine()
	config.appendCPUModel()
	config.appendQMPSockets()
	config.appendMemory()
	config.appendDevices()
	config.appendRTC()
	config.appendGlobalParam()
	config.appendVGA()
	config.appendKnobs()
	config.appendKernel()
	config.appendBios()
	config.appendIOThreads()
	config.appendIncoming()

	if err := config.appendCPUs(); err != nil {
		return "", err
	}

	ctx := config.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	return LaunchCustomQemu(ctx, config.Path, config.qemuParams,
		config.fds, nil, logger)
}

func LaunchCustomQemu(ctx context.Context, path string, params []string, fds []*os.File,
	attr *syscall.SysProcAttr, logger QMPLog) (string, error) {
	if logger == nil {
		logger = qmpNullLogger{}
	}

	errStr := ""

	if path == "" {
		path = "qemu-system-x86_64"
	}

	cmd := exec.CommandContext(ctx, path, params...)
	if len(fds) > 0 {
		logger.Infof("Adding extra file %v", fds)
		cmd.ExtraFiles = fds
	}

	cmd.SysProcAttr = attr

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	logger.Infof("launching %s with: %v", path, params)

	err := cmd.Run()
	if err != nil {
		logger.Errorf("Unable to launch %s: %v", path, err)
		errStr = stderr.String()
		logger.Errorf("%s", errStr)
	}
	return errStr, err
}
