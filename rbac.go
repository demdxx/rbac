package rbac

import (
	"context"

	"github.com/demdxx/xtypes"
)

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

	// List of wildcard permissions to preload
	// after role creation and register in the manager
	preloadPermissions []string

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

// CheckedPermission returns child permission for resource which has been checked as allowed
func (r *role) CheckedPermissions(ctx context.Context, resource any, names ...string) Permission {
	if len(names) == 0 {
		return nil
	}
	for _, p := range r.permissions {
		if perm := p.CheckedPermissions(ctx, resource, names...); perm != nil {
			return perm
		}
	}
	for _, r := range r.roles {
		if perm := r.CheckedPermissions(ctx, resource, names...); perm != nil {
			return perm
		}
	}
	return nil
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

// Permissions returns list of child permissions
func (r *role) Permissions(patterns ...string) []Permission {
	var result []Permission
	for _, p := range r.permissions {
		if len(patterns) == 0 || patterns[0] == `*` || p.MatchPermissionPattern(patterns...) {
			result = append(result, p)
		}
	}
	for _, r := range r.roles {
		result = append(result, r.Permissions(patterns...)...)
	}
	return result
}

// HasPermission returns true if permission has permission
func (r *role) HasPermission(patterns ...string) bool {
	return len(r.Permissions(patterns...)) > 0
}

// MatchPermissionPattern returns true if permission matches any of the patterns
func (r *role) MatchPermissionPattern(patterns ...string) bool {
	return false
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

// Prepare role for usage
func (r *role) Prepare(ctx context.Context, perms permissionReader) Role {
	if len(r.preloadPermissions) > 0 {
		r.AddPermissions(perms.Permissions(r.preloadPermissions...)...)
		r.preloadPermissions = nil
	}
	for i, role := range r.roles {
		switch rolei := role.(type) {
		case rolePreparer:
			r.roles[i] = rolei.Prepare(ctx, perms)
		}
	}
	return r
}

// AddPermissions to the role and remove duplicates
func (r *role) AddPermissions(permissions ...Permission) {
	r.permissions = append(r.permissions, permissions...)
	names := map[string]bool{}
	r.permissions = xtypes.Slice[Permission](r.permissions).Filter(func(p Permission) bool {
		name := p.Name()
		not := !names[name]
		if not {
			names[name] = true
		}
		return not
	})
}
