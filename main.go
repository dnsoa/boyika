package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
)

const (
	AppVersion            = "0.0.1"
	DefaultConfigFileName = "boyika.toml"
)

type App struct {
	wg    sync.WaitGroup
	quit  chan struct{}
	proxy Proxy
}

func main() {
	dlog.Init("boyika", dlog.SeverityNotice, "DAEMON")

	pwd, err := os.Getwd()
	if err != nil {
		dlog.Fatal("Unable to find the path to the current directory")
	}
	svcConfig := &service.Config{
		Name:             "boyika",
		DisplayName:      "博伊卡",
		Description:      "安全可靠快速的DNS服务器",
		WorkingDirectory: pwd,
	}
	svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
	app := &App{}
	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}
	app.proxy = NewProxy()
	if err := ConfigLoad(&app.proxy, svcFlag); err != nil {
		dlog.Fatal(err)
	}
	dlog.Noticef("boyika %s", AppVersion)

	if len(*svcFlag) != 0 {
		if svc == nil {
			dlog.Fatal("Built-in service installation is not supported on this platform")
		}
		if err := service.Control(svc, *svcFlag); err != nil {
			dlog.Fatal(err)
		}
		if *svcFlag == "install" {
			dlog.Notice("Installed as a service. Use `-service start` to start")
		} else if *svcFlag == "uninstall" {
			dlog.Notice("Service uninstalled")
		} else if *svcFlag == "start" {
			dlog.Notice("Service started")
		} else if *svcFlag == "stop" {
			dlog.Notice("Service stopped")
		} else if *svcFlag == "restart" {
			dlog.Notice("Service restarted")
		}
		return
	}
	if svc != nil {
		if err = svc.Run(); err != nil {
			dlog.Fatal(err)
		}
	} else {
		app.Start(nil)
	}
}

func (app *App) Start(service service.Service) error {
	proxy := &app.proxy
	if err := InitPluginsGlobals(&proxy.pluginsGlobals, proxy); err != nil {
		dlog.Fatal(err)
	}
	app.quit = make(chan struct{})
	app.wg.Add(1)
	if service != nil {
		go func() {
			app.AppMain(proxy)
		}()
	} else {
		app.AppMain(proxy)
	}
	return nil
}

func (app *App) AppMain(proxy *Proxy) {
	proxy.StartProxy()
	<-app.quit
	dlog.Notice("Quit signal received...")
	app.wg.Done()

}

func (app *App) Stop(service service.Service) error {
	dlog.Notice("Stopped.")
	return nil
}