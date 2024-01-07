package rbac

import "context"

// Role base interface
type Role interface {
	Permission

	// ChildRoles returns list of child roles
	ChildRoles() []Role

	// Role returns role by name
	Role(name string) Role

	// HasRole returns true if role has role
	HasRole(name string) bool
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

// ChildPermissions returns list of child permissions
func (r *role) ChildPermissions() []Permission {
	return r.permissions
}

// Permission returns child permission by name
func (r *role) Permission(name string) Permission {
	for _, p := range r.permissions {
		if p.Name() == name {
			return p
		} else if child := p.Permission(name); child != nil {
			return child
		}
	}
	for _, r := range r.roles {
		if p := r.Permission(name); p != nil {
			return p
		}
	}
	return nil
}

// HasPermission returns true if permission has permission
func (r *role) HasPermission(name string) bool {
	return r.Permission(name) != nil
}

// ChildRoles returns list of child roles
func (r *role) ChildRoles() []Role {
	return r.roles
}

// Role returns role by name
func (r *role) Role(name string) Role {
	if r.Name() == name {
		return r
	}
	for _, r := range r.roles {
		if r.Name() == name {
			return r
		} else if child := r.Role(name); child != nil {
			return child
		}
	}
	return nil
}

// HasRole returns true if role has role
func (r *role) HasRole(name string) bool {
	return r.Role(name) != nil
}

// Ext returns additional user data
func (r *role) Ext() any {
	return r.extData
}
