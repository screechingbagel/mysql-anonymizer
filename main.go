// data-anonymizer: a focused MySQL dump anonymizer.
//
// Usage:
//
//	mysqldump ... | data-anonymizer -c config.yaml | mysql ...
//
// Flags:
//
//	-c path     config file (default /nxs-data-anonymizer.conf)
//	-i path     input file  (default stdin)
//	-o path     output file (default stdout)
//	--cpuprofile path
//	--memprofile path
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"data-anonymizer/anon"
	"data-anonymizer/config"
	"data-anonymizer/mysql"
	"data-anonymizer/progress"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// ─── Flags ────────────────────────────────────────────────────────────────
	confPath := flag.String("c", "/nxs-data-anonymizer.conf", "Config file path")
	inputPath := flag.String("i", "", "Input file (default: stdin)")
	outputPath := flag.String("o", "", "Output file (default: stdout)")
	cpuProfile := flag.String("cpuprofile", "", "Write CPU profile to file")
	memProfile := flag.String("memprofile", "", "Write memory profile to file")
	flag.Parse()

	// ─── Context (signal + optional timeout) ──────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()


	// ─── Profiling ────────────────────────────────────────────────────────────
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			return fmt.Errorf("create CPU profile: %w", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "close CPU profile: %v\n", err)
			}
		}()
		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("start CPU profile: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	// ─── Config ───────────────────────────────────────────────────────────────
	cfg, err := config.Load(*confPath)
	if err != nil {
		return err
	}

	// ─── Input / output ───────────────────────────────────────────────────────
	var r io.Reader = os.Stdin
	if *inputPath != "" {
		f, err := os.Open(*inputPath)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "close input: %v\n", err)
			}
		}()
		r = f
	}

	var w io.Writer = os.Stdout
	if *outputPath != "" {
		f, err := os.Create(*outputPath)
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "close output: %v\n", err)
			}
		}()
		w = f
	}

	// ─── Progress ─────────────────────────────────────────────────────────────
	var rhythm time.Duration
	if cfg.Progress.Rhythm != "" {
		rhythm, err = time.ParseDuration(cfg.Progress.Rhythm)
		if err != nil {
			return fmt.Errorf("parse progress rhythm %q: %w", cfg.Progress.Rhythm, err)
		}
	}

	pr, stopProgress := progress.New(r, os.Stderr, rhythm, cfg.Progress.Humanize)
	defer stopProgress()
	r = pr

	// ─── Anonymizer ───────────────────────────────────────────────────────────
	a := anon.New(cfg.Rules)

	// ─── Run ──────────────────────────────────────────────────────────────────
	if err := mysql.Parse(ctx, r, w, a); err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// ─── Memory profile ───────────────────────────────────────────────────────
	if *memProfile != "" {
		f, err := os.Create(*memProfile)
		if err != nil {
			return fmt.Errorf("create memory profile: %w", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "close memory profile: %v\n", err)
			}
		}()
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("write memory profile: %w", err)
		}
	}

	return nil
}
