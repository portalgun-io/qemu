package qemu

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"syscall"
)

func CreateCloudInitISO(ctx context.Context, scratchDir, isoPath string,
	userData, metaData []byte, attr *syscall.SysProcAttr) error {
	configDrivePath := path.Join(scratchDir, "clr-cloud-init")
	dataDirPath := path.Join(configDrivePath, "openstack", "latest")
	metaDataPath := path.Join(dataDirPath, "meta_data.json")
	userDataPath := path.Join(dataDirPath, "user_data")

	defer func() {
		_ = os.RemoveAll(configDrivePath)
	}()

	err := os.MkdirAll(dataDirPath, 0750)
	if err != nil {
		return fmt.Errorf("Unable to create config drive directory %s : %v",
			dataDirPath, err)
	}

	err = ioutil.WriteFile(metaDataPath, metaData, 0644)
	if err != nil {
		return fmt.Errorf("Unable to create %s : %v", metaDataPath, err)
	}

	err = ioutil.WriteFile(userDataPath, userData, 0644)
	if err != nil {
		return fmt.Errorf("Unable to create %s : %v", userDataPath, err)
	}

	cmd := exec.CommandContext(ctx, "xorriso", "-as", "mkisofs", "-R", "-V", "config-2",
		"-o", isoPath, configDrivePath)
	cmd.SysProcAttr = attr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Unable to create cloudinit iso image %v", err)
	}

	return nil
}
