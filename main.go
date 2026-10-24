package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"fmt"
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
}

func (c *BuildCmd) Run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	projectRoot = ensureGoProject(projectRoot)

	if c.Clean {
		cleanDist(projectRoot)
	}

	goos := c.GOOS
	if goos == "" {
		goos = goEnv(projectRoot, "GOOS")
	}
	goarch := c.GOARCH
	if goarch == "" {
		goarch = goEnv(projectRoot, "GOARCH")
	}

	buildNative(projectRoot, goos, goarch)

	return nil
}

type BuildWasmCmd struct {
	Clean bool `help:"Remove dist before building."`
}

func (c *BuildWasmCmd) Run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	projectRoot = ensureGoProject(projectRoot)

	if c.Clean {
		cleanDist(projectRoot)
	}

	buildWasm(projectRoot)

	return nil
}

type ServeWebCmd struct {
	Addr    string `help:"Address to serve HTTP on." default:"localhost:8080"`
	TLSAddr string `name:"tls-addr" help:"Address to serve HTTPS on, with a self-signed certificate." default:"localhost:8443"`
}

func (c *ServeWebCmd) Run() error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}

	projectRoot = ensureGoProject(projectRoot)

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

			if err := buildWasmErr(projectRoot); err != nil {
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
	Build     BuildCmd     `cmd:"" help:"Build native binary."`
	BuildWasm BuildWasmCmd `cmd:"build-wasm" help:"Build WebAssembly version."`
	ServeWeb  ServeWebCmd  `cmd:"serve-web" help:"Serve the WebAssembly version, rebuilding on each reload."`
}

func main() {
	ctx := kong.Parse(&cli, kong.Description("Byke build tool"))
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

func ensureGoProject(start string) string {
	current, err := filepath.Abs(start)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
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

// goEnv runs in projectRoot so the same toolchain is selected as for the build.
func goEnv(projectRoot, name string) string {
	cmd := exec.Command("go", "env", name)
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

func buildNative(projectRoot, goos, goarch string) {
	outDir := filepath.Join(projectRoot, "dist", fmt.Sprintf("%s-%s", goos, goarch))
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	env := os.Environ()
	env = setupZigCCEnv(env, goos, goarch)
	env = setEnv(env, "GOOS", goos)
	env = setEnv(env, "GOARCH", goarch)

	checkRun([]string{"go", "build", "-o", outDir, "."}, projectRoot, env)

	if err := copyAssets(projectRoot, outDir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func buildWasm(projectRoot string) {
	if err := buildWasmErr(projectRoot); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func buildWasmErr(projectRoot string) error {
	outDir := filepath.Join(projectRoot, "dist", "wasm")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	env := os.Environ()
	env = setEnv(env, "GOOS", "js")
	env = setEnv(env, "GOARCH", "wasm")

	if err := run([]string{"go", "build", "-o", filepath.Join(outDir, "main.wasm"), "."}, projectRoot, env); err != nil {
		return err
	}

	goroot := goEnv(projectRoot, "GOROOT")

	wasmExec := filepath.Join(goroot, "lib", "wasm", "wasm_exec.js")
	if err := copyFile(wasmExec, filepath.Join(outDir, "wasm_exec.js"), 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(outDir, "index.html"), indexHTML, 0o644); err != nil {
		return err
	}

	return copyAssets(projectRoot, outDir)
}
