package main

import (
	"context"
	"ex-keygate/internal/config"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("部署安全配置校验失败", "error", err)
		os.Exit(1)
	}
	// Expose liveness only on loopback until business authentication is implemented.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"alive"}`))
	})
	server := &http.Server{
		Addr: "127.0.0.1:18760", Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		// Bound shutdown time so unfinished connections cannot block process termination.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("服务优雅退出失败", "error", err)
			_ = server.Close()
		}
	}()
	slog.Info("ExKeyGate 开发骨架启动，尚未提供认证能力", "address", server.Addr, "environment", cfg.Environment, "root_mode", cfg.RootMode)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("服务启动失败", "error", err)
		os.Exit(1)
	}
	<-shutdownDone
}
