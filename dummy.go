package rbac

import "context"

type dummy struct {
	name  string
	allow bool
}

// NewDummyPermission permission with predefined check
func NewDummyPermission(name string, allow bool) Permission                          { return &dummy{name: name, allow: allow} }
func (d *dummy) Name() string                                                        { return d.name }
func (d *dummy) CheckPermissions(_ context.Context, _ interface{}, _ ...string) bool { return d.allow }
