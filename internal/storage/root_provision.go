package storage

import (
	"context"
	"ex-keygate/internal/keycrypto"
)

// ProvisionSoftwareRootRequested 只有独立多人批准后才生成新的实际软件根材料。
// 持久运行先将材料封装至可信启动器；事务失败允许留下孤立密文，但绝不让未登记材料获得认证资格。
// 临时开发模式未配置封装器时，材料仍仅在内存，不能宣称可恢复。
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
	var material []byte
	if c.rootMaterial != nil {
		material, e = c.rootMaterial(m.Operation.RootID)
	} else {
		material, e = keycrypto.Generate()
	}
	if e != nil {
		return nil, e
	}
	defer clear(material)
	k, e := NewDevelopmentKeys(c, m.Operation.RootID, material, loginRootID)
	if e != nil {
		return nil, e
	}
	if c.rootPersistence != nil {
		if e = c.rootPersistence(k.rootID, material); e != nil {
			return nil, e
		}
	}
	p := &preparedKey{issueID: id, digest: digest, newRoot: k}
	if e = c.executePreparedAs(ctx, id, digest, trace, p, token); e != nil {
		return nil, e
	}
	return k, nil
}

// SetRootPersistence 仅供监听前可信启动器设置，不能由管理HTTP指定路径或导出根材料。
func (c *DevelopmentControl) SetRootPersistence(persist func(string, []byte) error, readers ...func(string) ([]byte, error)) {
	c.rootPersistence = persist
	if len(readers) == 1 {
		c.rootMaterial = readers[0]
	}
}
