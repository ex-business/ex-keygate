package storage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"ex-keygate/internal/access"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SearchFilter 的时间范围为创建时间左闭右开；游标只是查询位置，不携带读取或执行权限。
type SearchFilter struct {
	Query  string `json:"q"`
	From   string `json:"from"`
	Until  string `json:"until"`
	State  string `json:"state"`
	View   string `json:"view"`
	Unread bool   `json:"unread"`
	Limit  int    `json:"limit"`
	Cursor string `json:"-"`
}
type searchPosition struct {
	Offset int    `json:"offset"`
	Anchor string `json:"anchor"`
	Filter string `json:"filter"`
}
type RequestSearchPage struct {
	Items []ControlRequest `json:"items"`
	Next  string           `json:"nextCursor"`
}
type NoticeSearchPage struct {
	Items []ApprovalNotification `json:"items"`
	Next  string                 `json:"nextCursor"`
}

func normalizeSearch(f SearchFilter, notices bool) (SearchFilter, error) {
	f.Query = strings.TrimSpace(f.Query)
	if !utf8.ValidString(f.Query) || len(f.Query) > 256 || strings.ContainsFunc(f.Query, unicode.IsControl) {
		return f, ErrInvalid
	}
	if f.Limit == 0 {
		f.Limit = 20
	}
	if f.Limit < 1 || f.Limit > 50 || len(f.Cursor) > 1024 {
		return f, ErrInvalid
	}
	var from, until time.Time
	var e error
	if f.From != "" {
		from, e = time.Parse(time.RFC3339Nano, f.From)
		if e != nil {
			return f, ErrInvalid
		}
		f.From = from.UTC().Format(time.RFC3339Nano)
	}
	if f.Until != "" {
		until, e = time.Parse(time.RFC3339Nano, f.Until)
		if e != nil {
			return f, ErrInvalid
		}
		f.Until = until.UTC().Format(time.RFC3339Nano)
	}
	if !from.IsZero() && !until.IsZero() && !from.Before(until) {
		return f, ErrInvalid
	}
	if notices {
		if f.View != "" || f.State != "" {
			return f, ErrInvalid
		}
	} else {
		if f.Unread {
			return f, ErrInvalid
		}
		switch f.State {
		case "", "pending", "approved", "executed", "rejected", "expired", "withdrawn", "cancelled", "invalidated":
		default:
			return f, ErrInvalid
		}
		switch f.View {
		case "", "all", "mine", "applicant", "execute":
		default:
			return f, ErrInvalid
		}
	}
	return f, nil
}
func (c *DevelopmentControl) searchPosition(ctx context.Context, tx *sql.Tx, a controlActor, f SearchFilter, kind string) (searchPosition, error) {
	raw, _ := json.Marshal(f)
	fingerprint := digestBytes(append([]byte(c.environment+"\x00"+a.id+"\x00"+kind+"\x00"), raw...))
	if f.Cursor == "" {
		now, e := controlNow(ctx, tx)
		if kind == "requests" {
			now = now.Truncate(time.Millisecond)
		}
		return searchPosition{Anchor: now.UTC().Format(time.RFC3339Nano), Filter: fingerprint}, e
	}
	b, e := base64.RawURLEncoding.DecodeString(f.Cursor)
	if e != nil {
		return searchPosition{}, ErrInvalid
	}
	var p searchPosition
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return p, ErrInvalid
	}
	canonical, _ := json.Marshal(p)
	if string(canonical) != string(b) || p.Filter != fingerprint || p.Offset < 0 || p.Offset > 1000000 {
		return p, ErrInvalid
	}
	anchor, e := time.Parse(time.RFC3339Nano, p.Anchor)
	if e != nil {
		return p, ErrInvalid
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return p, e
	}
	if anchor.After(now) || (kind == "requests" && !anchor.Equal(anchor.Truncate(time.Millisecond))) {
		return p, ErrInvalid
	}
	return p, nil
}
func encodeSearchPosition(p searchPosition, consumed int) string {
	p.Offset += consumed
	if p.Offset > 1000000 {
		return ""
	}
	b, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(b)
}
func requestSearchState(r ControlRequest) string {
	if r.WithdrawnBy != "" {
		return "withdrawn"
	}
	if r.Expired && !r.Executed && (r.Decision == "pending" || r.Decision == "approved") {
		return "expired"
	}
	if r.Executed {
		return "executed"
	}
	if r.Invalidated {
		return "invalidated"
	}
	return r.Decision
}

// SearchRequests 固定首次查询时点并按不可变清单排序；每页最多复查200个候选，不把不可读记录的标识或总数放入响应。
// 局部撤权可能产生空页，但仍返回继续游标，避免最新100个不可读记录遮住更早的授权记录。
func (c *DevelopmentControl) SearchRequests(ctx context.Context, token string, f SearchFilter) (RequestSearchPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out := RequestSearchPage{Items: []ControlRequest{}}
	var e error
	f, e = normalizeSearch(f, false)
	if e != nil {
		return out, e
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return out, e
	}
	p, e := c.searchPosition(ctx, tx, a, f, "requests")
	if e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT request_id FROM (SELECT request_id,expires_at,convert_from(manifest,'UTF8')::jsonb AS m FROM keygate.control_requests WHERE environment=$1) r WHERE (m->>'created')::timestamptz<$2::timestamptz AND ($3='' OR (m->>'created')::timestamptz>=NULLIF($3,'')::timestamptz) AND ($4='' OR (m->>'created')::timestamptz<NULLIF($4,'')::timestamptz) AND ($5='' OR strpos(lower(concat_ws(' ',request_id,m->'operation'->>'clientId',m->'operation'->>'name',m->'applicant'->>'personId',m->'applicant'->>'principalId')),lower($5))>0) ORDER BY expires_at DESC,request_id DESC LIMIT 201 OFFSET $6`, c.environment, p.Anchor, f.From, f.Until, f.Query, p.Offset)
	if e != nil {
		return out, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return out, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	consumed := 0
	for i, id := range ids {
		if i == 200 || len(out.Items) == f.Limit {
			break
		}
		consumed++
		r, m, e := c.loadRequest(ctx, tx, id)
		if e != nil {
			return out, e
		}
		permitted := c.requestViewer(ctx, tx, a.id, m.Operation) || (a.id == m.Applicant.PrincipalID && c.has(ctx, tx, a.id, access.Requester, operationScope(m.Operation)))
		if !permitted {
			_, e = c.currentMember(ctx, tx, m, a.id)
			if e == nil {
				permitted = true
			} else if !errors.Is(e, ErrDenied) && !errors.Is(e, ErrConflict) {
				return out, e
			}
		}
		if !permitted || (f.State != "" && requestSearchState(r) != f.State) {
			continue
		}
		switch f.View {
		case "applicant":
			if a.id != m.Applicant.PrincipalID {
				continue
			}
		case "execute":
			if a.id != m.Applicant.PrincipalID || requestSearchState(r) != "approved" {
				continue
			}
		case "mine":
			if requestSearchState(r) != "pending" {
				continue
			}
			if _, e = c.currentMember(ctx, tx, m, a.id); e != nil {
				if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
					continue
				}
				return out, e
			}
			if m.Sequential {
				if r.Progress == nil || r.Progress.CurrentPrincipalID != a.id {
					continue
				}
			} else {
				if _, e = c.currentMember(ctx, tx, m, a.id); e != nil {
					if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
						continue
					}
					return out, e
				}
				var voted bool
				if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.control_votes WHERE environment=$1 AND request_id=$2 AND principal_id=$3)`, c.environment, id, a.id).Scan(&voted); e != nil {
					return out, e
				}
				if voted {
					continue
				}
			}
		}
		out.Items = append(out.Items, r)
	}
	if consumed < len(ids) {
		out.Next = encodeSearchPosition(p, consumed)
	}
	return out, tx.Commit()
}

// SearchNotifications 始终限制本人收件人并复查冻结资格；搜索不扫描原因、操作载荷或秘密字段。
func (c *DevelopmentControl) SearchNotifications(ctx context.Context, token string, f SearchFilter) (NoticeSearchPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out := NoticeSearchPage{Items: []ApprovalNotification{}}
	var e error
	f, e = normalizeSearch(f, true)
	if e != nil {
		return out, e
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return out, e
	}
	p, e := c.searchPosition(ctx, tx, a, f, "notifications")
	if e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT `+noticeColumns+` FROM keygate.approval_notifications WHERE environment=$1 AND recipient_id=$2 AND created_at<=$3::timestamptz AND ($4='' OR created_at>=NULLIF($4,'')::timestamptz) AND ($5='' OR created_at<NULLIF($5,'')::timestamptz) AND ($6='' OR strpos(lower(concat_ws(' ',id,request_id,kind)),lower($6))>0) ORDER BY created_at DESC,id DESC LIMIT 201 OFFSET $7`, c.environment, a.id, p.Anchor, f.From, f.Until, f.Query, p.Offset)
	if e != nil {
		return out, e
	}
	items := []ApprovalNotification{}
	for rows.Next() {
		v, e := scanApprovalNotice(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	consumed := 0
	for i, v := range items {
		if i == 200 || len(out.Items) == f.Limit {
			break
		}
		consumed++
		_, m, e := c.loadRequest(ctx, tx, v.RequestID)
		if e != nil {
			return out, e
		}
		allowed, e := c.noticeRecipient(ctx, tx, m, a.id)
		if e != nil {
			return out, e
		}
		if allowed && (!f.Unread || !v.Read) {
			out.Items = append(out.Items, v)
		}
	}
	if consumed < len(items) {
		out.Next = encodeSearchPosition(p, consumed)
	}
	return out, tx.Commit()
}
