package main

import (
	"encoding/json"
	"errors"
	"ex-keygate/internal/storage"
	"ex-keygate/internal/trustnotify"
	"ex-keygate/provider"
	"ex-keygate/trustchain"
)

// 告警配置只从受控私有文件读取，传输固定IP和mTLS复用已验收的提醒插件，邮件短信由插件维护组映射。
func loadAlertDelivery(path string) (map[string]storage.AlertBinding, func(), error) {
	bindings := map[string]storage.AlertBinding{}
	plugins := []*trustnotify.Plugin{}
	closeAll := func() {
		for _, p := range plugins {
			p.Close()
		}
	}
	if path == "" {
		return bindings, closeAll, nil
	}
	raw, e := readPrivate(path)
	if e != nil {
		return nil, closeAll, errors.New("告警投递配置不可用")
	}
	var cfg struct {
		Routes []struct {
			storage.AlertRoute
			Plugin trustnotify.Config `json:"plugin"`
		} `json:"routes"`
	}
	if provider.DecodeStrict(raw, &cfg) != nil || len(cfg.Routes) < 1 || len(cfg.Routes) > 12 {
		return nil, closeAll, errors.New("告警投递配置无效")
	}
	for _, v := range cfg.Routes {
		if _, ok := bindings[v.ID]; ok {
			closeAll()
			return nil, closeAll, errors.New("告警路由标识重复")
		}
		plugin, e := trustnotify.New(v.Plugin)
		if e != nil {
			closeAll()
			return nil, closeAll, errors.New("告警投递插件初始化失败")
		}
		plugins = append(plugins, plugin)
		ca, e := trustchain.ReadFile(v.Plugin.CAFile, false)
		if e != nil {
			closeAll()
			return nil, closeAll, e
		}
		cert, e := trustchain.ReadFile(v.Plugin.CertificateFile, false)
		if e != nil {
			closeAll()
			return nil, closeAll, e
		}
		// 依赖快照会改写临时文件路径；摘要依据公开证书和路由内容计算，正常重启不会凭路径生成新路由。
		material, _ := json.Marshal(struct {
			Route           storage.AlertRoute
			URL             string
			IPs             []string
			CA, Certificate []byte
		}{v.AlertRoute, v.Plugin.URL, v.Plugin.AllowedIPs, ca, cert})
		v.Digest = storage.ConfigurationDigest(material)
		bindings[v.ID] = storage.AlertBinding{Route: v.AlertRoute, Plugin: plugin}
	}
	return bindings, closeAll, nil
}
