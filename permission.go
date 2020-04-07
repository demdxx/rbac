package rbac

import (
	"context"
	"errors"
	"reflect"
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

	// CheckPermissions to accept to resource
	CheckPermissions(ctx context.Context, resource interface{}, names ...string) bool
}

// SimplePermission implementation with simple functionality
type SimplePermission struct {
	name            string
	extData         interface{}
	checkFnkResType reflect.Type
	checkFnk        reflect.Value // func(ctx, resource, names ...string)
	permissions     []Permission
}

// NewSimplePermission object with custom checker
func NewSimplePermission(name string, options ...Option) (Permission, error) {
	perm := &SimplePermission{name: name}
	for _, opt := range options {
		if err := opt(perm); err != nil {
			return nil, err
		}
	}
	return perm, nil
}

// MustNewSimplePermission with name and resource type
func MustNewSimplePermission(name string, options ...Option) Permission {
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

// CheckPermissions to accept to resource
func (perm *SimplePermission) CheckPermissions(ctx context.Context, resource interface{}, names ...string) bool {
	if len(names) == 0 {
		panic(ErrInvalidCheckParams)
	}
	if indexOfStrArr(perm.name, names) && perm.callCallback(ctx, resource, names...) {
		return true
	}
	for _, p := range perm.permissions {
		if p.CheckPermissions(ctx, resource, names...) {
			return true
		}
	}
	return false
}

func (perm *SimplePermission) callCallback(ctx context.Context, resource interface{}, names ...string) bool {
	if perm.checkFnk.Kind() != reflect.Func {
		return true
	}

	// Get reflect resource value
	res := reflect.ValueOf(resource)

	// Check first parameter type
	if perm.checkFnkResType.Kind() != reflect.Interface && perm.checkFnkResType != res.Type() {
		return false
	}
	in := []reflect.Value{reflect.ValueOf(ctx), res}
	for _, name := range names {
		in = append(in, reflect.ValueOf(name))
	}
	if resp := perm.checkFnk.Call(in); len(resp) == 1 {
		return resp[0].Bool()
	}
	return false
}

// RosourcePermission implementation for some specific object type
type RosourcePermission struct {
	SimplePermission
	resType reflect.Type
}

// NewRosourcePermission object with custom checker and base type
func NewRosourcePermission(name string, resType interface{}, options ...Option) (Permission, error) {
	perm := &RosourcePermission{
		SimplePermission: SimplePermission{name: name},
		resType:          getResType(resType),
	}
	if perm.resType == nil {
		return nil, ErrInvalidResouceType
	}
	for _, opt := range options {
		if err := opt(perm); err != nil {
			return nil, err
		}
	}
	return perm, nil
}

// MustNewRosourcePermission with name and resource type
func MustNewRosourcePermission(name string, resType interface{}, options ...Option) Permission {
	perm, err := NewRosourcePermission(name, resType, options...)
	if err != nil {
		panic(err)
	}
	return perm
}

// CheckPermissions to accept to resource
func (perm *RosourcePermission) CheckPermissions(ctx context.Context, resource interface{}, names ...string) bool {
	if indexOfStrArr(perm.name, names) && perm.CheckType(resource) && perm.callCallback(ctx, resource, names...) {
		return true
	}
	for _, p := range perm.permissions {
		if p.CheckPermissions(ctx, resource, names...) {
			return true
		}
	}
	return false
}

// CheckType of resource and target type
func (perm *RosourcePermission) CheckType(resource interface{}) bool {
	var res reflect.Type
	switch t := resource.(type) {
	case nil:
	case reflect.Type:
		res = t
	default:
		res = reflect.TypeOf(resource)
	}
	return perm.resType == res
}

func indexOfStrArr(s string, arr []string) bool {
	for _, v := range arr {
		if v == s {
			return true
		}
	}
	return false
}

func getResType(resource interface{}) (res reflect.Type) {
	switch r := resource.(type) {
	case nil:
	case reflect.Type:
		res = r
	default:
		res = reflect.TypeOf(resource)
	}
	for res.Kind() == reflect.Interface {
		res = res.Elem()
	}
	return res
}
