package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
)

type Config struct {
	LogLevel        int      `toml:"log_level"`
	LogFile         *string  `toml:"log_file"`
	UseSyslog       bool     `toml:"use_syslog"`
	UpdateServer    string   `toml:update_server`
	Daemonize                bool
	ListenAddresses []string `toml:"listen_addresses"`
}

func newConfig() Config {
	return Config{
		LogLevel:        int(dlog.LogLevel()),
		ListenAddresses: []string{"127.0.0.1:53"},
	}
}

func findConfigFile(configFile *string) (string, error) {
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		cdLocal()
		if _, err := os.Stat(*configFile); err != nil {
			return "", err
		}
	}
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(*configFile) {
		return *configFile, nil
	}
	return path.Join(pwd, *configFile), nil
}

func ConfigLoad(proxy *Proxy, svcFlag *string) error {
	version := flag.Bool("version", false, "print current proxy version")
	check := flag.Bool("check", false, "check the configuration file and exit")
	configFile := flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	child := flag.Bool("child", false, "Invokes program as a child process")

	flag.Parse()

	if *svcFlag == "stop" || *svcFlag == "uninstall" {
		return nil
	}
	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	foundConfigFile, err := findConfigFile(configFile)
	if err != nil {
		dlog.Fatalf("Unable to load the configuration file [%s] -- Maybe use the -config command-line switch?", *configFile)
	}
	config := newConfig()
	md, err := toml.DecodeFile(foundConfigFile, &config)
	if err != nil {
		return err
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return fmt.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
	}
	cdFileDir(foundConfigFile)
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
		if !*child {
			FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
		} else {
			FileDescriptorNum++
			dlog.SetFileDescriptor(os.NewFile(uintptr(3), "logFile"))
		}
	}
	proxy.listenAddresses = config.ListenAddresses
	proxy.daemonize = config.Daemonize

	if *check {
		dlog.Notice("Configuration successfully checked")
		os.Exit(0)
	}
	return nil
}



func cdFileDir(fileName string) {
	os.Chdir(filepath.Dir(fileName))
}

func cdLocal() {
	exeFileName, err := os.Executable()
	if err != nil {
		dlog.Warnf("Unable to determine the executable directory: [%s] -- You will need to specify absolute paths in the configuration file", err)
		return
	}
	os.Chdir(filepath.Dir(exeFileName))
}

func netProbe(address string, timeout int) error {
	if len(address) <= 0 || timeout <= 0 {
		return nil
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	retried := false
	for tries := timeout; tries > 0; tries-- {
		pc, err := net.DialUDP("udp", nil, remoteUDPAddr)
		if err != nil {
			if !retried {
				retried = true
				dlog.Notice("Network not available yet -- waiting...")
			}
			dlog.Debug(err)
			time.Sleep(1 * time.Second)
			continue
		}
		pc.Close()
		if retried {
			dlog.Notice("Network connectivity detected")
		}
		return nil
	}
	es := "Timeout while waiting for network connectivity"
	dlog.Error(es)
	return errors.New(es)
}
