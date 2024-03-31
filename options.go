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

// WithDescription of the role or permission
func WithDescription(description string) Option {
	return func(obj any) error {
		switch o := obj.(type) {
		case *role:
			o.description = description
		case *SimplePermission:
			o.description = description
		case *ResourcePermission:
			o.description = description
		default:
			return wrapError(ErrInvalidOption, `WithDescription`)
		}
		return nil
	}
}

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

// WithPermissions apply subpermission
func WithPermissions(permissions ...any) Option {
	vecPermissions := make([]Permission, 0, len(permissions))
	verPermPreload := make([]string, 0, len(permissions))
	for _, p := range permissions {
		switch vl := p.(type) {
		case Permission:
			vecPermissions = append(vecPermissions, vl)
		case []Permission:
			vecPermissions = append(vecPermissions, vl...)
		case string:
			verPermPreload = append(verPermPreload, vl)
		case []string:
			verPermPreload = append(verPermPreload, vl...)
		default:
			panic(wrapError(ErrInvalidOptionParam, `WithPermissions`))
		}
	}
	return func(obj any) error {
		switch o := obj.(type) {
		case *SimplePermission:
			o.permissions = vecPermissions
			if len(verPermPreload) > 0 {
				return wrapError(ErrInvalidOptionParam, `WithPermissions::SimplePermission (preload permissions not allowed)`)
			}
		case *ResourcePermission:
			o.permissions = vecPermissions
			if len(verPermPreload) > 0 {
				return wrapError(ErrInvalidOptionParam, `WithPermissions::ResourcePermission (preload permissions not allowed)`)
			}
		case *role:
			o.permissions = vecPermissions
			o.preloadPermissions = verPermPreload
		default:
			return wrapError(ErrInvalidOption, `WithPermissions`)
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
//	perm := NewResourcePermission(`view`, &model.User{}, WithCustomCheck(callback, &roleContext))
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
		case *ResourcePermission:
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

// WithoutCustomCheck remove custom check
func WithoutCustomCheck(obj any) error {
	switch o := obj.(type) {
	case *SimplePermission:
		o.checkFnk = reflect.Value{}
	case *ResourcePermission:
		o.checkFnk = reflect.Value{}
	default:
		return wrapError(ErrInvalidOption, `WithoutCustomCheck`)
	}
	return nil
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
		case *ResourcePermission:
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
