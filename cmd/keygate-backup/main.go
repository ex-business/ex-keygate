// keygate-backup 是独立受控运维进程，不部署为管理接口，也不在认证节点内持有备份签名私钥。
package main

import (
	"context"
	"encoding/json"
	"ex-keygate/internal/auditarchive"
	"ex-keygate/internal/backup"
	"ex-keygate/provider"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error("备份或恢复任务失败，禁止自动恢复认证", "result", "failed")
		os.Exit(1)
	}
}
func run() error {
	action := flag.String("action", "", "backup / checkpoint / run / restore")
	config := flag.String("config", "", "独立私有备份配置文件")
	backupID := flag.String("backup-id", "", "要恢复的备份标识")
	latest := flag.String("latest-checkpoint", "", "备份之外独立最新检查点")
	expected := flag.String("expected-checkpoint-sha256", "", "由独立可信见证固定的最新文件摘要")
	target := flag.String("target-database-file", "", "预建隔离空库的私有连接配置")
	confirm := flag.String("confirm-empty-target", "", "明确确认目标数据库名称")
	flag.Parse()
	if *action != "backup" && *action != "checkpoint" && *action != "run" && *action != "restore" {
		return backup.ErrBackup
	}
	raw, e := auditarchive.ReadPrivate(*config, 1<<20)
	if e != nil {
		return backup.ErrBackup
	}
	var cfg backup.Config
	if provider.DecodeStrict(raw, &cfg) != nil {
		return backup.ErrBackup
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	job, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	r, e := backup.Open(job, cfg, *action != "restore")
	if e != nil {
		return e
	}
	defer r.Close()
	if *action == "run" {
		r.Run(ctx, func(kind string, v backup.Result, e error) {
			if e != nil {
				slog.Error("自动备份或检查点保存失败", "task", kind, "environment", cfg.Environment, "result", "failed")
			} else {
				slog.Info("自动备份或检查点已保存，请同步独立见证", "task", kind, "environment", cfg.Environment, "checkpoint_id", v.ID, "checkpoint_sha256", v.CheckpointSHA256, "backup_id", v.BackupID, "result", "saved")
			}
		})
		return nil
	}
	if *action == "restore" {
		if e = r.Restore(job, *backupID, *latest, *expected, *target, *confirm); e != nil {
			return e
		}
		fmt.Println(`{"result":"quarantined","authenticationEnabled":false}`)
		return nil
	}
	var result backup.Result
	if *action == "backup" {
		result, e = r.Backup(job)
	} else {
		result, e = r.Checkpoint(job)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
