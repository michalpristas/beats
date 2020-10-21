package main

import (
	"fmt"
	"os"
	"time"
)

const filename = "/Users/michalpristas/go/src/github.com/elastic/beats/x-pack/forkplay/forkfile.out"
const delay = 30 * time.Second

func main() {
	f, _ := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0640)
	defer f.Close()

	fmt.Fprintf(f, "starting %v\n", time.Now())

	<-time.After(delay)
	fmt.Fprintf(f, "stopping %v\n", time.Now())
}
