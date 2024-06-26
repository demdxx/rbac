package rbac

import "context"

type dummy struct {
	name  string
	allow bool
}

// NewDummyPermission permission with predefined check
func NewDummyPermission(name string, allow bool) Role                        { return &dummy{name: name, allow: allow} }
func (d *dummy) Name() string                                                { return d.name }
func (d *dummy) Description() string                                         { return "" }
func (d *dummy) CheckPermissions(_ context.Context, _ any, _ ...string) bool { return d.allow }
func (d *dummy) ChildPermissions() []Permission                              { return nil }
func (d *dummy) Permission(_ string) Permission                              { return nil }
func (d *dummy) Permissions(_ ...string) []Permission                        { return nil }
func (d *dummy) HasPermission(_ ...string) bool                              { return false }
func (d *dummy) MatchPermissionPattern(_ ...string) bool                     { return false }
func (d *dummy) ChildRoles() []Role                                          { return nil }
func (d *dummy) Role(_ string) Role                                          { return nil }
func (d *dummy) HasRole(_ string) bool                                       { return false }
func (d *dummy) Ext() any                                                    { return nil }
func (d *dummy) CheckedPermissions(_ context.Context, _ any, _ ...string) Permission {
	if d.allow {
		return d
	}
	return nil
}
