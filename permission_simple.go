package rbac

import (
	"context"
	"reflect"
)

// SimplePermission implementation with simple functionality
type SimplePermission struct {
	name            string
	description     string
	extData         any
	checkFnkResType reflect.Type
	checkFnk        reflect.Value // func(ctx, resource, names ...string)
	permissions     []Permission
}

// NewSimplePermission object with custom checker
func NewSimplePermission(name string, options ...Option) (*SimplePermission, error) {
	if err := validatePermissionName(name); err != nil {
		return nil, err
	}
	perm := &SimplePermission{name: name}
	for _, opt := range options {
		if err := opt(perm); err != nil {
			return nil, err
		}
	}
	return perm, nil
}

// MustNewSimplePermission with name and resource type
func MustNewSimplePermission(name string, options ...Option) *SimplePermission {
	perm, err := NewSimplePermission(name, options...)
	if err != nil {
		panic(err)
	}
	return perm
}

// Name of the permission
func (perm *SimplePermission) Name() string {
	return perm.name
}

// Description of the permission
func (perm *SimplePermission) Description() string {
	return perm.description
}

// CheckPermissions to accept to resource
func (perm *SimplePermission) CheckPermissions(ctx context.Context, resource any, patterns ...string) bool {
	if len(patterns) == 0 {
		panic(ErrInvalidCheckParams)
	}
	return perm.CheckedPermissions(ctx, resource, patterns...) != nil
}

// CheckedPermission returns child permission for resource which has been checked as allowed
func (perm *SimplePermission) CheckedPermissions(ctx context.Context, resource any, patterns ...string) Permission {
	if len(patterns) == 0 || perm == nil {
		return nil
	}
	if perm.MatchPermissionPattern(patterns...) && perm.callCallback(ctx, nil, resource, patterns...) {
		return perm
	}
	for _, p := range perm.permissions {
		if r := p.CheckedPermissions(ctx, resource, patterns...); r != nil {
			return r
		}
	}
	return nil
}

// ChildPermissions returns list of child permissions
func (perm *SimplePermission) ChildPermissions() []Permission {
	return perm.permissions
}

// Permission returns permission by name
func (perm *SimplePermission) Permission(name string) Permission {
	if perm.name == name {
		return perm
	}
	for _, p := range perm.permissions {
		if p.Name() == name {
			return p
		} else if child := p.Permission(name); child != nil {
			return child
		}
	}
	return nil
}

// Permissions returns list of permissions by pattern
func (perm *SimplePermission) Permissions(patterns ...string) []Permission {
	if perm == nil || len(patterns) == 0 {
		return nil
	}
	var res []Permission
	if perm.MatchPermissionPattern(patterns...) {
		res = append(res, perm)
	}
	for _, p := range perm.permissions {
		if p.MatchPermissionPattern(patterns...) {
			res = append(res, p)
		}
		if child := p.Permissions(patterns...); len(child) > 0 {
			res = append(res, child...)
		}
	}
	return res
}

// HasPermission returns true if permission has permission
func (perm *SimplePermission) HasPermission(patterns ...string) bool {
	return perm.MatchPermissionPattern(patterns...) || len(perm.Permissions(patterns...)) > 0
}

// MatchPermissionPattern returns true if permission matches any of the patterns
func (perm *SimplePermission) MatchPermissionPattern(patterns ...string) bool {
	return perm != nil && checkPattern(perm.name, patterns...)
}

// Ext returns additional user data
func (perm *SimplePermission) Ext() any {
	return perm.extData
}

func (perm *SimplePermission) callCallback(ctx context.Context, curPerm Permission, resource any, _ ...string) bool {
	if perm.checkFnk.Kind() != reflect.Func {
		return true
	}

	// Get reflect resource value
	res := reflect.ValueOf(resource)

	// Check first parameter type
	if perm.checkFnkResType.Kind() != reflect.Interface && perm.checkFnkResType != res.Type() {
		return false
	}
	if curPerm == nil {
		curPerm = perm
	}
	in := []reflect.Value{
		reflect.ValueOf(ctx), res,
		reflect.ValueOf((Permission)(curPerm)),
	}
	if resp := perm.checkFnk.Call(in); len(resp) == 1 {
		return resp[0].Bool()
	}
	return false
}
