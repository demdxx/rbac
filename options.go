package rbac

import (
	"errors"
	"reflect"
)

var (
	// ErrInvalidOption for this type
	ErrInvalidOption = errors.New(`invalid option`)

	// ErrInvalidOptionParam if param is not valid
	ErrInvalidOptionParam = errors.New(`invalid option param`)
)

// Option apply function to object
type Option func(obj any) error

// WithChildRoles of the role
func WithChildRoles(roles ...Role) Option {
	return func(obj any) error {
		switch o := obj.(type) {
		case *role:
			o.roles = roles
		default:
			return wrapError(ErrInvalidOption, `WithChildRoles`)
		}
		return nil
	}
}

// WithSubPermissins apply subpermission
func WithSubPermissins(permissions ...Permission) Option {
	return func(obj any) error {
		switch o := obj.(type) {
		case *SimplePermission:
			o.permissions = permissions
		case *RosourcePermission:
			o.permissions = permissions
		case *role:
			o.permissions = permissions
		default:
			return wrapError(ErrInvalidOption, `WithSubPermissins`)
		}
		return nil
	}
}

// WithCustomCheck function and additional data if need to use in checker
// Example:
//
//	callback := func(ctx context.Context, resource any, names ...string) bool {
//	  return ExtData(ctx).(*model.RoleContext).DebugMode
//	}
//	perm := NewRosourcePermission(`view`, &model.User{}, WithCustomCheck(callback, &roleContext))
func WithCustomCheck(f any, data ...any) Option {
	return func(obj any) error {
		if f == nil {
			return wrapError(ErrInvalidOptionParam, `WithCustomCheck`)
		}
		var dataVal any
		if len(data) > 0 {
			dataVal = data[0]
		}
		switch o := obj.(type) {
		case *SimplePermission:
			o.checkFnk = reflect.ValueOf(f)
			ftype := o.checkFnk.Type()
			if ftype.NumIn() != 3 {
				return wrapError(ErrInvalidOptionParam, `WithCustomCheck::callback`)
			}
			o.checkFnkResType = ftype.In(0)
			o.extData = dataVal
		case *RosourcePermission:
			o.checkFnk = reflect.ValueOf(f)
			ftype := o.checkFnk.Type()
			if ftype.NumIn() != 3 {
				return wrapError(ErrInvalidOptionParam, `WithCustomCheck::callback`)
			}
			o.checkFnkResType = ftype.In(0)
			if o.checkFnkResType.Kind() != reflect.Interface && o.checkFnkResType != o.resType {
				return wrapError(ErrInvalidOptionParam, `WithCustomCheck::(callback invalid argument != resource.Type)`)
			}
			o.extData = dataVal
		default:
			return wrapError(ErrInvalidOption, `WithCustomCheck`)
		}
		return nil
	}
}

// WithExtData for the role or permission
func WithExtData(data any) Option {
	type setExtI interface {
		SetExtData(data any)
	}
	return func(obj any) error {
		switch o := obj.(type) {
		case *SimplePermission:
			o.extData = data
		case *RosourcePermission:
			o.extData = data
		case *role:
			o.extData = data
		case setExtI:
			o.SetExtData(data)
		default:
			return wrapError(ErrInvalidOption, `WithExtData`)
		}
		return nil
	}
}
