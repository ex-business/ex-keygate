package storage

import (
	"context"
	"ex-keygate/internal/keycrypto"
)

// ProvisionSoftwareRootRequested 只有独立多人批准后才生成新的实际软件根材料。
// 材料仅留在调用进程；事务成功但进程丢失材料时，该根不可恢复，必须审批另一个新根，不能复用别名。
func (c *DevelopmentControl) ProvisionSoftwareRootRequested(ctx context.Context, token, id, digest, trace, loginRootID string) (*DevelopmentKeys, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return nil, e
	}
	if e = c.executionActor(ctx, tx, token, m); e != nil {
		return nil, e
	}
	if r.Executed || r.Digest != digest || m.Operation.Kind != ProvisionRoot || r.Decision != "approved" || m.Applicant.GrantScope != "" {
		return nil, ErrConflict
	}
	if e = c.liveManifest(ctx, tx, m); e != nil {
		return nil, e
	}
	if e = c.verifyVotes(ctx, tx, m); e != nil {
		return nil, e
	}
	if e = c.validateOperation(ctx, tx, m.Operation); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	material, e := keycrypto.Generate()
	if e != nil {
		return nil, e
	}
	defer clear(material)
	k, e := NewDevelopmentKeys(c, m.Operation.RootID, material, loginRootID)
	if e != nil {
		return nil, e
	}
	p := &preparedKey{issueID: id, digest: digest, newRoot: k}
	if e = c.executePreparedAs(ctx, id, digest, trace, p, token); e != nil {
		return nil, e
	}
	return k, nil
}
