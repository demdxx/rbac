package rbac

import (
	"reflect"

	"github.com/pkg/errors"
)

var (
	// ErrInvalidOption for this type
	ErrInvalidOption = errors.New(`invalid option`)

	// ErrInvalidOptionParam if param is not valid
	ErrInvalidOptionParam = errors.New(`invalid option param`)
)

// Option apply function to object
type Option func(obj interface{}) error

// WithChildRoles of the role
func WithChildRoles(roles ...Role) Option {
	return func(obj interface{}) error {
		switch o := obj.(type) {
		case *role:
			o.roles = roles
		default:
			return errors.Wrap(ErrInvalidOption, `WithChildRoles`)
		}
		return nil
	}
}

// WithSubPermissins apply subpermission
func WithSubPermissins(permissions ...Permission) Option {
	return func(obj interface{}) error {
		switch o := obj.(type) {
		case *SimplePermission:
			o.permissions = permissions
		case *RosourcePermission:
			o.permissions = permissions
		case *role:
			o.permissions = permissions
		default:
			return errors.Wrap(ErrInvalidOption, `WithSubPermissins`)
		}
		return nil
	}
}

// WithCustomCheck function
func WithCustomCheck(f interface{}) Option {
	return func(obj interface{}) error {
		if f == nil {
			return errors.Wrap(ErrInvalidOptionParam, `WithCustomCheck`)
		}
		switch o := obj.(type) {
		case *SimplePermission:
			o.checkFnk = reflect.ValueOf(f)
			ftype := o.checkFnk.Type()
			if ftype.NumIn() != 2 {
				return errors.Wrap(ErrInvalidOptionParam, `WithCustomCheck::callback`)
			}
			o.checkFnkResType = ftype.In(0)
		case *RosourcePermission:
			o.checkFnk = reflect.ValueOf(f)
			ftype := o.checkFnk.Type()
			if ftype.NumIn() != 2 {
				return errors.Wrap(ErrInvalidOptionParam, `WithCustomCheck::callback`)
			}
			o.checkFnkResType = ftype.In(0)
			if o.checkFnkResType.Kind() != reflect.Interface && o.checkFnkResType != o.resType {
				return errors.Wrap(ErrInvalidOptionParam, `WithCustomCheck::(callback invalid argument != resource.Type)`)
			}
		default:
			return errors.Wrap(ErrInvalidOption, `WithCustomCheck`)
		}
		return nil
	}
}
