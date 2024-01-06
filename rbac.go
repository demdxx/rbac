package rbac

import "context"

// Role base interface
type Role interface {
	Permission
	ChildRoles() []Role
}

// Role base object
type role struct {
	// Name of the role
	name string

	// List of linked roles
	roles []Role

	// List of permissions
	permissions []Permission

	// Additional data
	extData any
}

// NewRole interface implementation
func NewRole(name string, options ...Option) (Role, error) {
	role := &role{name: name}
	for _, opt := range options {
		if err := opt(role); err != nil {
			return nil, err
		}
	}
	return role, nil
}

// MustNewRole or produce panic
func MustNewRole(name string, options ...Option) Role {
	role, err := NewRole(name, options...)
	if err != nil {
		panic(err)
	}
	return role
}

// Name of the role
func (r *role) Name() string {
	return r.name
}

// CheckPermissions of some resource
func (r *role) CheckPermissions(ctx context.Context, resource any, names ...string) bool {
	if len(names) == 0 {
		panic(ErrInvalidCheckParams)
	}
	for _, p := range r.permissions {
		if p.CheckPermissions(ctx, resource, names...) {
			return true
		}
	}
	for _, r := range r.roles {
		if r.CheckPermissions(ctx, resource, names...) {
			return true
		}
	}
	return false
}

// ChildRoles returns list of child roles
func (r *role) ChildRoles() []Role {
	return r.roles
}

// ChildPermissions returns list of child permissions
func (r *role) ChildPermissions() []Permission {
	return r.permissions
}

// Ext returns additional user data
func (r *role) Ext() any {
	return r.extData
}
