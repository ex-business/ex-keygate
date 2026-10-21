package trustnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"ex-keygate/internal/storage"
	"io"
	"net/http"
	"time"
)

// SendSystemAlert 固定业务载荷排除尝试次数和内部队列状态，插件按ID去重；接收确认不能代表邮件已读或短信送达。
func (p *Plugin) SendSystemAlert(ctx context.Context, v storage.AlertMessage) error {
	payload := struct {
		ID         string    `json:"id"`
		IncidentID string    `json:"incidentId"`
		EventID    string    `json:"eventId"`
		RouteID    string    `json:"routeId"`
		Channel    string    `json:"channel"`
		Target     string    `json:"target"`
		Kind       string    `json:"kind"`
		Code       string    `json:"code"`
		NodeID     string    `json:"nodeId"`
		ObservedAt time.Time `json:"observedAt"`
		Path       string    `json:"path"`
	}{v.ID, v.IncidentID, v.EventID, v.RouteID, v.Channel, v.Target, v.Kind, v.Code, v.NodeID, v.ObservedAt, "/manage#monitoring"}
	raw, e := json.Marshal(payload)
	if e != nil {
		return ErrPlugin
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(raw))
	if e != nil {
		return ErrPlugin
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", v.ID)
	response, e := p.client.Do(req)
	if e != nil {
		return ErrPlugin
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return ErrPlugin
	}
	return nil
}
