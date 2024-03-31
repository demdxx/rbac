package rbac

import (
	"context"
	"errors"
)

var (
	// ErrInvalidCheckParams in case of empty permission check params
	ErrInvalidCheckParams = errors.New(`invalid check params`)

	// ErrInvalidResouceType if parameter is Nil
	ErrInvalidResouceType = errors.New(`invalid resource type`)
)

// Permission object checker
type Permission interface {
	Name() string

	// Description of the permission
	Description() string

	// CheckPermissions to accept to resource
	CheckPermissions(ctx context.Context, resource any, patterns ...string) bool

	// CheckedPermission returns child permission for resource which has been checked as allowed
	CheckedPermissions(ctx context.Context, resource any, patterns ...string) Permission

	// ChildPermissions list returns list of child permissions
	ChildPermissions() []Permission

	// Permission returns permission by name
	Permission(name string) Permission

	// Permissions returns list of permissions by pattern
	Permissions(patterns ...string) []Permission

	// HasPermission returns true if permission has child permission
	HasPermission(patterns ...string) bool

	// MatchPermissionPattern returns true if permission matches any of the patterns
	MatchPermissionPattern(patterns ...string) bool

	// Ext returns additional user data
	Ext() any
}
