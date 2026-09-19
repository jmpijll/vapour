package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config-file", "", "read one JSON service config and run until stdin closes")
	flag.StringVar(&configPath, "config", "", "alias for -config-file")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}

	var err error
	if configPath == "" {
		err = runProtocol(os.Stdin, os.Stdout)
	} else {
		err = runConfigFile(configPath, os.Stdin, os.Stdout)
	}
	if err != nil {
		os.Exit(1)
	}
}

type statusSink struct {
	buffer  *bufio.Writer
	encoder *json.Encoder
}

func newStatusSink(output io.Writer) *statusSink {
	buffer := bufio.NewWriter(output)
	return &statusSink{buffer: buffer, encoder: json.NewEncoder(buffer)}
}

func (s *statusSink) write(status statusMessage) error {
	if err := s.encoder.Encode(status); err != nil {
		return err
	}
	return s.buffer.Flush()
}

func writeError(sink *statusSink, err error) error {
	if err == nil {
		return nil
	}
	return sink.write(statusMessage{Status: "error", Error: err.Error()})
}

type serviceRuntime struct {
	service *dnsService
	engine  *domainEngine
}

func (r *serviceRuntime) start(input config) (statusMessage, error) {
	if r.service != nil {
		return statusMessage{}, errors.New("DNS service is already running")
	}
	validated, err := validateConfig(input)
	if err != nil {
		return statusMessage{}, err
	}
	engine, err := newDomainEngine(validated.Rules)
	if err != nil {
		return statusMessage{}, err
	}
	service, err := newDNSService(validated, engine)
	if err != nil {
		return statusMessage{}, err
	}
	if err := service.start(); err != nil {
		_ = service.shutdown()
		return statusMessage{}, err
	}
	udpAddrs := service.udpAddrs()
	tcpAddrs := service.tcpAddrs()
	listenerCount := 1
	if validated.DualStack {
		listenerCount = 2
	}
	if validated.Transparent {
		listenerCount = len(validated.ListenAddresses)
	}
	if len(udpAddrs) != listenerCount || len(tcpAddrs) != listenerCount {
		_ = service.shutdown()
		return statusMessage{}, errors.New("DNS proxy started without the expected listener addresses")
	}
	if validated.Transparent {
		if err := validateTransparentReady(validated, udpAddrs, tcpAddrs, service.slotStatus()); err != nil {
			return statusMessage{}, errors.Join(err, service.shutdown())
		}
	}

	r.service = service
	r.engine = engine
	return statusMessage{
		Status:     "ready",
		UDPAddr:    udpAddrs[0],
		TCPAddr:    tcpAddrs[0],
		UDPAddrs:   udpAddrs,
		TCPAddrs:   tcpAddrs,
		RulesCount: engine.rulesCount(),
		Slots:      service.slotStatus(),
	}, nil
}

func (r *serviceRuntime) stop() error {
	if r.service == nil {
		return nil
	}
	service := r.service
	r.service = nil
	r.engine = nil
	return service.shutdown()
}

func runProtocol(input io.Reader, output io.Writer) error {
	sink := newStatusSink(output)
	runtime := &serviceRuntime{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxCommandBytes)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var request command
		if err := decodeJSON([]byte(line), &request); err != nil {
			if writeErr := writeError(sink, fmt.Errorf("decode command: %w", err)); writeErr != nil {
				_ = runtime.stop()
				return writeErr
			}
			continue
		}

		switch request.Op {
		case "register", "release":
			var commandErr error
			if runtime.service == nil || request.Flow == nil {
				commandErr = errors.New("flow command requires a running service and flow")
			} else if request.Op == "register" {
				commandErr = runtime.service.registerFlow(*request.Flow)
			} else {
				commandErr = runtime.service.releaseFlow(*request.Flow)
			}
			if commandErr != nil {
				if err := writeError(sink, commandErr); err != nil {
					_ = runtime.stop()
					return err
				}
				continue
			}
			status := "registered"
			if request.Op == "release" {
				status = "released"
			}
			if err := sink.write(statusMessage{Status: status}); err != nil {
				_ = runtime.stop()
				return err
			}
		case "start":
			if request.Config == nil {
				if err := writeError(sink, errors.New("start requires config")); err != nil {
					_ = runtime.stop()
					return err
				}
				continue
			}
			ready, err := runtime.start(*request.Config)
			if err != nil {
				if writeErr := writeError(sink, err); writeErr != nil {
					_ = runtime.stop()
					return writeErr
				}
				continue
			}
			if err := sink.write(ready); err != nil {
				_ = runtime.stop()
				return err
			}
		case "reload":
			var reloadErr error
			var engine *domainEngine
			if runtime.service == nil {
				reloadErr = errors.New("DNS service is not running")
			} else if request.Rules == nil {
				reloadErr = errors.New("reload requires rules")
			} else {
				engine, reloadErr = newDomainEngine(*request.Rules)
			}
			if reloadErr != nil {
				if err := writeError(sink, reloadErr); err != nil {
					_ = runtime.stop()
					return err
				}
				continue
			}
			// Publish only a completely parsed engine. Each request retains its
			// snapshot while the old engine is reclaimed by Go's garbage collector.
			runtime.service.engine.Store(engine)
			runtime.engine = engine
			if err := sink.write(statusMessage{Status: "updated", RulesCount: engine.rulesCount()}); err != nil {
				_ = runtime.stop()
				return err
			}
		case "stop":
			stopErr := runtime.stop()
			if stopErr != nil {
				if err := writeError(sink, stopErr); err != nil {
					return err
				}
			}
			if err := sink.write(statusMessage{Status: "stopped"}); err != nil {
				return err
			}
			return stopErr
		default:
			if err := writeError(sink, fmt.Errorf("unsupported command op %q", request.Op)); err != nil {
				_ = runtime.stop()
				return err
			}
		}
	}

	resultErr := scanner.Err()
	if resultErr != nil {
		if err := writeError(sink, fmt.Errorf("read command stream: %w", resultErr)); err != nil {
			_ = runtime.stop()
			return err
		}
	}
	if err := runtime.stop(); err != nil {
		if writeErr := writeError(sink, err); writeErr != nil {
			return writeErr
		}
		if resultErr == nil {
			resultErr = err
		}
	}
	if err := sink.write(statusMessage{Status: "stopped"}); err != nil {
		return err
	}
	return resultErr
}

func runConfigFile(path string, input io.Reader, output io.Writer) error {
	sink := newStatusSink(output)
	data, err := readBoundedFile(path, maxCommandBytes)
	if err != nil {
		if writeErr := writeError(sink, err); writeErr != nil {
			return writeErr
		}
		_ = sink.write(statusMessage{Status: "stopped"})
		return err
	}
	requested, err := decodeConfig(data)
	if err == nil && requested.Transparent {
		err = errors.New("transparent DNS requires the command protocol for flow registration")
	}
	if err != nil {
		if writeErr := writeError(sink, err); writeErr != nil {
			return writeErr
		}
		_ = sink.write(statusMessage{Status: "stopped"})
		return err
	}

	runtime := &serviceRuntime{}
	ready, err := runtime.start(requested)
	if err != nil {
		if writeErr := writeError(sink, err); writeErr != nil {
			return writeErr
		}
		_ = sink.write(statusMessage{Status: "stopped"})
		return err
	}
	if err := sink.write(ready); err != nil {
		_ = runtime.stop()
		return err
	}

	// Config-file mode has no command stream.  Holding the parent pipe open
	// keeps the resolver alive; closing it is the shutdown signal.
	resultErr := error(nil)
	if _, err := io.Copy(io.Discard, input); err != nil {
		resultErr = err
		if writeErr := writeError(sink, fmt.Errorf("read parent stream: %w", err)); writeErr != nil {
			_ = runtime.stop()
			return writeErr
		}
	}
	if err := runtime.stop(); err != nil {
		if writeErr := writeError(sink, err); writeErr != nil {
			return writeErr
		}
		if resultErr == nil {
			resultErr = err
		}
	}
	if err := sink.write(statusMessage{Status: "stopped"}); err != nil {
		return err
	}
	return resultErr
}

func decodeConfig(data []byte) (config, error) {
	var target config
	if err := decodeJSON(data, &target); err != nil {
		return config{}, fmt.Errorf("decode config: %w", err)
	}
	return target, nil
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("config file path is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("config file exceeds %d bytes", maxBytes)
	}
	return data, nil
}
