package webauth

// PersistentProfileDigest 仅供可信启动器绑定原登录配置，不提供HTTP导出。
func (s *Service) PersistentProfileDigest() string { return s.profile }

// SetPersistentRootWriter 监听前安装加密根写入器；旧的临时开发模式不受影响。
func (s *Service) SetPersistentRootWriter(writer func(string, []byte) error, reader func(string) ([]byte, error)) error {
	if s.handlerStarted.Load() || s.flow == nil || writer == nil || reader == nil {
		return ErrConfig
	}
	s.flow.control.SetRootPersistence(writer, reader)
	return nil
}
