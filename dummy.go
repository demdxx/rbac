package rbac

import "context"

type dummy struct {
	name  string
	allow bool
}

// NewDummyPermission permission with predefined check
func NewDummyPermission(name string, allow bool) Role                        { return &dummy{name: name, allow: allow} }
func (d *dummy) Name() string                                                { return d.name }
func (d *dummy) CheckPermissions(_ context.Context, _ any, _ ...string) bool { return d.allow }
func (d *dummy) ChildPermissions() []Permission                              { return nil }
func (d *dummy) ChildRoles() []Role                                          { return nil }
func (d *dummy) Ext() any                                                    { return nil }
