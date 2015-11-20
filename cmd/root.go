// Copyright ©2015 Steve Francia <spf@spf13.com>
//
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/caddy"
	"github.com/mholt/caddy/caddy/letsencrypt"
	"github.com/spf13/cobra"
)

const (
	appName    = "Caddy"
	appVersion = "0.8 beta 4"
)

var (
	conf    string
	cpu     string
	logfile string
	revoke  string
)

//Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

// rootCmd respresents the root command
var RootCmd = &cobra.Command{
	Use:   "caddy",
	Short: "Caddy is a lightweight, general-purpose web server",
	Long: `Caddy is a lightweight, general-purpose web server for Windows, Mac, Linux, BSD, and Android

It is a capable alternative to other popular and easy to use web servers.

The most notable features are HTTP/2, Let's Encrypt support, Virtual Hosts, TLS + SNI, and easy configuration with a Caddyfile. In development, you usually put one Caddyfile with each site. In production, Caddy serves HTTPS by default and manages all cryptographic assets for you. `,

	Run: func(cmd *cobra.Command, args []string) {
		// set up process log before anything bad happens
		switch logfile {
		case "stdout":
			log.SetOutput(os.Stdout)
		case "stderr":
			log.SetOutput(os.Stderr)
		case "":
			log.SetOutput(ioutil.Discard)
		default:
			file, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				log.Fatalf("Error opening process log file: %v", err)
			}
			log.SetOutput(file)
		}

		if revoke != "" {
			err := letsencrypt.Revoke(revoke)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Revoked certificate for %s\n", revoke)
			os.Exit(0)
		}

		// Set CPU cap
		err := setCPU(cpu)
		if err != nil {
			mustLogFatal(err)
		}

		// Get Caddyfile input
		caddyfile, err := caddy.LoadCaddyfile(loadCaddyfile)
		if err != nil {
			mustLogFatal(err)
		}

		// Start your engines
		err = caddy.Start(caddyfile)
		if err != nil {
			mustLogFatal(err)
		}

		// Twiddle your thumbs
		caddy.Wait()
	},
}

func init() {
	caddy.AppName = appName
	caddy.AppVersion = appVersion

	caddy.TrapSignals()
	RootCmd.PersistentFlags().BoolVar(&letsencrypt.Agreed, "agree", false, "Agree to Let's Encrypt Subscriber Agreement")
	RootCmd.PersistentFlags().StringVar(&letsencrypt.CAUrl, "ca", "https://acme-staging.api.letsencrypt.org/directory", "Certificate authority ACME server")
	RootCmd.PersistentFlags().StringVar(&conf, "conf", "", "Configuration file to use (default="+caddy.DefaultConfigFile+")")
	RootCmd.PersistentFlags().StringVar(&cpu, "cpu", "100%", "CPU cap")
	RootCmd.PersistentFlags().StringVar(&letsencrypt.DefaultEmail, "email", "", "Default Let's Encrypt account email address")
	RootCmd.PersistentFlags().DurationVar(&caddy.GracefulTimeout, "grace", 5*time.Second, "Maximum duration of graceful shutdown")
	RootCmd.PersistentFlags().StringVar(&caddy.Host, "host", caddy.DefaultHost, "Default host")
	RootCmd.PersistentFlags().BoolVar(&caddy.HTTP2, "http2", true, "HTTP/2 support") // TODO: temporary flag until http2 merged into std lib
	RootCmd.PersistentFlags().StringVar(&logfile, "log", "", "Process log file")
	RootCmd.PersistentFlags().StringVar(&caddy.PidFile, "pidfile", "", "Path to write pid file")
	RootCmd.PersistentFlags().StringVar(&caddy.Port, "port", caddy.DefaultPort, "Default port")
	RootCmd.PersistentFlags().BoolVar(&caddy.Quiet, "quiet", false, "Quiet mode (no initialization output)")
	RootCmd.PersistentFlags().StringVar(&revoke, "revoke", "", "Hostname for which to revoke the certificate")
	RootCmd.PersistentFlags().StringVar(&caddy.Root, "root", caddy.DefaultRoot, "Root path to default site")
}

// mustLogFatal just wraps log.Fatal() in a way that ensures the
// output is always printed to stderr so the user can see it
// if the user is still there, even if the process log was not
// enabled. If this process is a restart, however, and the user
// might not be there anymore, this just logs to the process log
// and exits.
func mustLogFatal(args ...interface{}) {
	if !caddy.IsRestart() {
		log.SetOutput(os.Stderr)
	}
	log.Fatal(args...)
}

func loadCaddyfile() (caddy.Input, error) {
	// Try -conf flag
	if conf != "" {
		if conf == "stdin" {
			return caddy.CaddyfileFromPipe(os.Stdin)
		}

		contents, err := ioutil.ReadFile(conf)
		if err != nil {
			return nil, err
		}

		return caddy.CaddyfileInput{
			Contents: contents,
			Filepath: conf,
			RealFile: true,
		}, nil
	}

	// command line args
	if flag.NArg() > 0 {
		confBody := caddy.Host + ":" + caddy.Port + "\n" + strings.Join(flag.Args(), "\n")
		return caddy.CaddyfileInput{
			Contents: []byte(confBody),
			Filepath: "args",
		}, nil
	}

	// Caddyfile in cwd
	contents, err := ioutil.ReadFile(caddy.DefaultConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return caddy.DefaultInput(), nil
		}
		return nil, err
	}
	return caddy.CaddyfileInput{
		Contents: contents,
		Filepath: caddy.DefaultConfigFile,
		RealFile: true,
	}, nil
}

// setCPU parses string cpu and sets GOMAXPROCS
// according to its value. It accepts either
// a number (e.g. 3) or a percent (e.g. 50%).
func setCPU(cpu string) error {
	var numCPU int

	availCPU := runtime.NumCPU()

	if strings.HasSuffix(cpu, "%") {
		// Percent
		var percent float32
		pctStr := cpu[:len(cpu)-1]
		pctInt, err := strconv.Atoi(pctStr)
		if err != nil || pctInt < 1 || pctInt > 100 {
			return errors.New("invalid CPU value: percentage must be between 1-100")
		}
		percent = float32(pctInt) / 100
		numCPU = int(float32(availCPU) * percent)
	} else {
		// Number
		num, err := strconv.Atoi(cpu)
		if err != nil || num < 1 {
			return errors.New("invalid CPU value: provide a number or percent greater than 0")
		}
		numCPU = num
	}

	if numCPU > availCPU {
		numCPU = availCPU
	}

	runtime.GOMAXPROCS(numCPU)
	return nil
}
