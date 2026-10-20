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

// SendApprovalNotification 只传固定的管理入口与收件身份标识；插件自行维护经核验的邮件/短信路由，不接受申请人指定地址。
func (p *Plugin) SendApprovalNotification(ctx context.Context, v storage.ApprovalNotification) error {
	payload := struct {
		ID          string    `json:"id"`
		RequestID   string    `json:"requestId"`
		RecipientID string    `json:"recipientId"`
		Kind        string    `json:"kind"`
		Digest      string    `json:"digest"`
		ExpiresAt   time.Time `json:"expiresAt"`
		CreatedAt   time.Time `json:"createdAt"`
		Path        string    `json:"path"`
	}{v.ID, v.RequestID, v.RecipientID, v.Kind, v.Digest, v.ExpiresAt, v.CreatedAt, "/manage#approvals"}
	raw, e := json.Marshal(payload)
	if e != nil {
		return ErrPlugin
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(raw))
	if e != nil {
		return ErrPlugin
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", v.ID)
	response, e := p.client.Do(r)
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
