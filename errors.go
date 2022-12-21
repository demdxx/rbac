package rbac

type errorWrapper struct {
	err error
	msg string
}

func (w *errorWrapper) Error() string { return w.msg + ": " + w.err.Error() }
func (w *errorWrapper) Unwrap() error { return w.err }

func wrapError(err error, msg string) error {
	return &errorWrapper{err: err, msg: msg}
}
