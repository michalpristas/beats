package main

import (
	"context"
	"fmt"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/upgrade"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/logger"
)

func main() {
	log, _ := logger.New("demo")
	ch := make(chan error, 1)
	c, err := upgrade.NewCrashChecker(context.Background(), ch, log)
	if err != nil {
		fmt.Println("checker failed", err)
		return
	}

	fmt.Println("service controll", c.SC.Name())
	pid, err := c.SC.PID(context.Background())
	fmt.Println("agent pid:", pid, err)
}
