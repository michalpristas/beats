package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const filename = "mainfile.out"
const delay = 10 * time.Second

func main() {
	f, _ := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0640)
	defer f.Close()

	fmt.Fprintf(f, "starting %v\n", time.Now())
	if err := forkit(); err != nil {
		fmt.Fprintf(f, "error %v\n", err)
	}

	<-time.After(delay)

	fmt.Fprintf(f, "stopping %v\n", time.Now())
}

func forkit() error {
	cmd := exec.Command("./subfork")
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	cmd.Dir = wd

	return cmd.Start()
}
