package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
)

//go:embed index.html
var indexHTML []byte

type BuildCmd struct {
	Clean  bool   `help:"Remove dist before building."`
	GOOS   string `name:"os" help:"Target GOOS (defaults to current Go environment)."`
	GOARCH string `name:"arch" help:"Target GOARCH (defaults to current Go environment)."`
	UseZig bool   `name:"use-zig" help:"Use zig as the C compiler for cgo."`
}

func (c *BuildCmd) Run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	ensureGoProject(projectRoot)

	if c.Clean {
		cleanDist(projectRoot)
	}

	goos := c.GOOS
	if goos == "" {
		goos = toolEnv(projectRoot, "go", "GOOS")
	}
	goarch := c.GOARCH
	if goarch == "" {
		goarch = toolEnv(projectRoot, "go", "GOARCH")
	}

	buildNative(projectRoot, goos, goarch, c.UseZig)

	return nil
}

type BuildWebCmd struct {
	Clean       bool `help:"Remove dist before building."`
	SkipWasmOpt bool `name:"skip-wasm-opt" help:"Do not optimize main.wasm with wasm-opt."`
	TinyGo      bool `name:"tinygo" help:"Build with TinyGo. Needs the fork at github.com/oliverbestmann/tinygo."`
}

func (c *BuildWebCmd) Run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	ensureGoProject(projectRoot)

	if c.Clean {
		cleanDist(projectRoot)
	}

	buildWasm(projectRoot, !c.SkipWasmOpt, c.TinyGo)

	return nil
}

type PgoCmd struct {
	Duration time.Duration `help:"How long to run the game offscreen." default:"30s"`
}

func (c *PgoCmd) Run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	ensureGoProject(projectRoot)

	// write to a temporary file first, so a failed run keeps the previous profile
	profile := filepath.Join(projectRoot, "default.pgo")
	tmpProfile := profile + ".tmp"

	env := os.Environ()
	env = setEnv(env, "BYKE_CPUPROFILE", tmpProfile)
	env = setEnv(env, "BYKE_OFFSCREEN_DURATION", c.Duration.String())

	fmt.Printf("Running offscreen for %s\n", c.Duration)
	if err := run([]string{"go", "run", "."}, projectRoot, env); err != nil {
		_ = os.Remove(tmpProfile)
		return fmt.Errorf("run game: %w", err)
	}

	if err := os.Rename(tmpProfile, profile); err != nil {
		return err
	}

	fmt.Printf("Wrote %s\n", profile)
	return nil
}

type ServeWebCmd struct {
	Addr    string `help:"Address to serve HTTP on." default:"localhost:8080"`
	TLSAddr string `name:"tls-addr" help:"Address to serve HTTPS on, with a self-signed certificate." default:"localhost:8443"`
	TinyGo  bool   `name:"tinygo" help:"Build with TinyGo. Needs the fork at github.com/oliverbestmann/tinygo."`
}

func (c *ServeWebCmd) Run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	ensureGoProject(projectRoot)

	outDir := filepath.Join(projectRoot, "dist", "wasm")

	fileServer := http.FileServer(http.Dir(outDir))

	// serializes builds and keeps file requests from reading half-written output
	var mu sync.Mutex

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		// rebuild once per page load, not for every file the page fetches
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			fmt.Printf("Building wasm for %s\n", r.URL.Path)

			// skip wasm-opt to keep reloads fast
			if err := buildWasmErr(projectRoot, false, c.TinyGo); err != nil {
				http.Error(w, fmt.Sprintf("build failed: %v", err), http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Cache-Control", "no-store")
		fileServer.ServeHTTP(w, r)
	})

	cert, err := selfSignedCert(c.TLSAddr)
	if err != nil {
		return err
	}

	tlsServer := &http.Server{
		Addr:      c.TLSAddr,
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	errc := make(chan error, 2)
	go func() { errc <- http.ListenAndServe(c.Addr, handler) }()
	go func() { errc <- tlsServer.ListenAndServeTLS("", "") }()

	fmt.Printf("Serving on http://%s and https://%s\n", c.Addr, c.TLSAddr)

	return <-errc
}

// selfSignedCert creates an in-memory certificate for localhost and the host of addr.
func selfSignedCert(addr string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "byke-cli"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if host != "" && host != "localhost" {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

var cli struct {
	Build    BuildCmd    `cmd:"" help:"Build native binary."`
	BuildWeb BuildWebCmd `cmd:"build-web" help:"Build WebAssembly version."`
	ServeWeb ServeWebCmd `cmd:"serve-web" help:"Serve the WebAssembly version, rebuilding on each reload."`
	Pgo      PgoCmd      `cmd:"" help:"Run the game offscreen natively and write a CPU profile to default.pgo."`
}

func main() {
	ctx := kong.Parse(&cli, kong.Description("Byke build tool"))
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

// ensureGoProject exits unless start is inside a Go module. Commands still build
// the package in start, so this works for examples in a module subdirectory.
func ensureGoProject(start string) {
	current, err := filepath.Abs(start)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return
		}

		parent := filepath.Dir(current)
		if parent == current {
			fmt.Fprintln(os.Stderr, "error: could not find go.mod in this directory or any parent")
			os.Exit(1)
		}
		current = parent
	}
}

func run(cmd []string, cwd string, env []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Dir = cwd
	c.Env = env
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}

func checkRun(cmd []string, cwd string, env []string) {
	if err := run(cmd, cwd, env); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// toolEnv runs "tool env name" in projectRoot so the same toolchain is selected as for the build.
func toolEnv(projectRoot, tool, name string) string {
	cmd := exec.Command(tool, "env", name)
	cmd.Dir = projectRoot
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(out))
}

func cleanDist(projectRoot string) {
	dist := filepath.Join(projectRoot, "dist")
	if _, err := os.Stat(dist); err == nil {
		fmt.Printf("Removing %s\n", dist)
		if err := os.RemoveAll(dist); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
}

func copyAssets(projectRoot, destination string) error {
	assets := filepath.Join(projectRoot, "assets")
	if info, err := os.Stat(assets); err != nil || !info.IsDir() {
		return nil
	}

	fmt.Println("Copy assets")
	return copyDir(assets, filepath.Join(destination, "assets"))
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}

		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}

func setupZigCCEnv(env []string, goos, goarch string) []string {
	targets := map[[2]string]string{
		{"linux", "amd64"}:   "x86_64-linux-gnu",
		{"linux", "arm64"}:   "aarch64-linux-gnu",
		{"darwin", "amd64"}:  "x86_64-macos",
		{"darwin", "arm64"}:  "aarch64-macos",
		{"windows", "amd64"}: "x86_64-windows-gnu",
		{"windows", "arm64"}: "aarch64-windows-gnu",
	}

	target, ok := targets[[2]string{goos, goarch}]

	cc := "zig cc"
	cxx := "zig c++"
	if ok {
		cc = fmt.Sprintf("zig cc -target %s", target)
		cxx = fmt.Sprintf("zig c++ -target %s", target)
	}

	env = setEnv(env, "CC", cc)
	env = setEnv(env, "CXX", cxx)
	return env
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func buildNative(projectRoot, goos, goarch string, useZig bool) {
	outDir := filepath.Join(projectRoot, "dist", fmt.Sprintf("%s-%s", goos, goarch))
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	env := os.Environ()
	if useZig {
		env = setupZigCCEnv(env, goos, goarch)
	}
	env = setEnv(env, "GOOS", goos)
	env = setEnv(env, "GOARCH", goarch)

	fmt.Println("Building application")
	checkRun([]string{"go", "build", "-o", outDir, "."}, projectRoot, env)

	if err := copyAssets(projectRoot, outDir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func buildWasm(projectRoot string, optimize, tinygo bool) {
	if err := buildWasmErr(projectRoot, optimize, tinygo); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// tinygoTarget is the TinyGo wasm target with simd enabled.
const tinygoTarget = `{
	"inherits": ["wasm"],
	"features": "+bulk-memory,+bulk-memory-opt,+call-indirect-overlong,+mutable-globals,+nontrapping-fptoint,+sign-ext,+simd128,-multivalue,-reference-types",
	"cflags": ["-msimd128"]
}
`

func buildWasmErr(projectRoot string, optimize, tinygo bool) error {
	outDir := filepath.Join(projectRoot, "dist", "wasm")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	env := os.Environ()
	env = setEnv(env, "GOOS", "js")
	env = setEnv(env, "GOARCH", "wasm")
	env = setEnv(env, "CGO_ENABLED", "0")

	mainWasm := filepath.Join(outDir, "main.wasm")

	// enable the wasm features the Go compiler emits, so wasm-opt accepts the input,
	// and simd so wasm-opt may use it
	buildCmd := []string{"go", "build", "-o", mainWasm, "."}
	optCmd := []string{
		"wasm-opt", "-O2",
		"--enable-bulk-memory", "--enable-nontrapping-float-to-int", "--enable-sign-ext", "--enable-simd",
		mainWasm, "-o", mainWasm,
	}

	var wasmExec string
	if tinygo {
		// outside dist/wasm, so it is not served
		target := filepath.Join(projectRoot, "dist", "tinygo-wasm-simd.json")
		if err := os.WriteFile(target, []byte(tinygoTarget), 0o644); err != nil {
			return err
		}

		// nosimd: TinyGo does not implement simd/archsimd, which byke glm uses with Go 1.27's default goexperiment.simd
		buildCmd = []string{
			"tinygo", "build", "-no-debug", "-fatal-runtime-errors", "-opt=3", "-tags=nosimd",
			"-target", target, "-o", mainWasm, ".",
		}

		optCmd = []string{
			"wasm-opt", "-O3", "--strip-debug", "--strip-producers",
			"--enable-bulk-memory", "--enable-bulk-memory-opt", "--enable-mutable-globals",
			"--enable-nontrapping-float-to-int", "--enable-sign-ext", "--enable-simd",
			mainWasm, "-o", mainWasm,
		}

		wasmExec = filepath.Join(toolEnv(projectRoot, "tinygo", "TINYGOROOT"), "targets", "wasm_exec.js")
	} else {
		wasmExec = filepath.Join(toolEnv(projectRoot, "go", "GOROOT"), "lib", "wasm", "wasm_exec.js")
	}

	fmt.Println("Building application")
	if err := run(buildCmd, projectRoot, env); err != nil {
		return err
	}

	if optimize {
		fmt.Println("Optimizing wasm")
		if err := run(optCmd, projectRoot, env); err != nil {
			return fmt.Errorf("wasm-opt: %w", err)
		}
	}

	fmt.Println("Copy helper files")
	if err := copyFile(wasmExec, filepath.Join(outDir, "wasm_exec.js"), 0o644); err != nil {
		return err
	}

	html, err := os.ReadFile(filepath.Join(projectRoot, "index.html"))
	if errors.Is(err, fs.ErrNotExist) {
		html, err = indexHTML, nil
	}
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(outDir, "index.html"), html, 0o644); err != nil {
		return err
	}

	return copyAssets(projectRoot, outDir)
}
