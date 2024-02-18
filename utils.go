package rbac

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
)

var (
	ErrEmptyPermissionName   = errors.New(`empty permission name`)
	ErrInvalidPermissionName = errors.New(`invalid permission name`)
)

// checkPattern checks if the string matches any of the patterns
//
// Example:
// checkPattern(`test.it`, `test.*`) => true
// checkPattern(`test.it`, `test.*`, `test2`) => true
// checkPattern(`test.it.owner`, `test.*.*`, `test2.*`) => true
// checkPattern(`test.it.admin`, `test.*.owner`) => false
func checkPattern(name string, patterns ...string) bool {
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

// checkResourcePattern checks if the resource name matches any of the patterns
//
// Example:
// checkResourcePattern(`test.Object`, `owner`, `*`,) => true
// checkResourcePattern(`test.Object`, `register.owner`, `register.*`) => true
// checkResourcePattern(`test.Object`, `register.owner`, `test.Object.register.*`) => true
func checkResourcePattern(resName, name string, patterns ...string) bool {
	fullName := resName + `.` + name
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, fullName); ok {
			return true
		}
		if ok, _ := filepath.Match(resName+`.`+pattern, fullName); ok {
			return true
		}
	}
	return false
}

// GetResName returns resource name
func GetResName(resource any) string {
	type rName interface {
		RBACResourceName() string
	}
	switch t := resource.(type) {
	case nil:
		return ``
	case rName:
		return t.RBACResourceName()
	}
	tp := GetResType(resource)
	if tp.Kind() != reflect.Struct {
		return ``
	}
	packageName := filepath.Base(tp.PkgPath())
	if packageName == `` {
		return tp.Name()
	}
	return packageName + `.` + tp.Name()
}

// GetResType returns resource type
func GetResType(resource any) (res reflect.Type) {
	switch r := resource.(type) {
	case nil:
		return nil
	case reflect.Type:
		res = r
	case reflect.Value:
		res = r.Type()
	default:
		res = reflect.TypeOf(resource)
	}
	for res.Kind() == reflect.Interface || res.Kind() == reflect.Ptr {
		res = res.Elem()
	}
	return res
}

func validatePermissionName(name string) error {
	if name == `` {
		return ErrEmptyPermissionName
	}
	if strings.Contains(name, `*`) {
		return wrapError(ErrInvalidPermissionName, `permission name contains wildcard * -> `+name)
	}
	return nil
}
