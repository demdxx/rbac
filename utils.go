package rbac

import (
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

var (
	ErrEmptyPermissionName   = errors.New(`empty permission name`)
	ErrInvalidPermissionName = errors.New(`invalid permission name`)
	ErrInvalidPattern        = errors.New(`invalid pattern`)
)

func nextBlockIndex(pattern string, start int) int {
	for i := start; i < len(pattern); i++ {
		if pattern[i] == '.' {
			return i
		}
	}
	return len(pattern)
}

// MatchName permission pattern
// Example:
// `*` or `**` matches any string
// `test.*` matches `test.it`, `test.it.owner`, `test.it.admin
// `test.*.owner` matches `test.it.owner`, `test.object.owner`
// `test.*.*` matches `test.it.owner`, `test.object.owner`
// `test.*.?wner` matches `test.it.owner`, `test.object.owner
// `test.*.{owner|admin}` matches `test.it.owner`, `test.object.admin`
// `test.%r{[a-z]+}` matches `test.it.owner`, `test.object.admin` (regexp)
// `test.**` matches `test.it.owner`, `test.object.admin` (** must be at the end)
func MatchName(pattern, name string) (ok bool, err error) {
	if pattern == `*` || pattern == `**` {
		return true, nil
	}

	for nsi, psi := 0, 0; ; {
		// Search pattern block
		nnpi := nextBlockIndex(name, nsi)
		pnpi := nextBlockIndex(pattern, psi)

		if pnpi <= psi {
			return nnpi <= nsi, nil
		}
		if nnpi <= nsi {
			return false, nil
		}

		curNamePart := name[nsi:nnpi]
		curPattern := pattern[psi:pnpi]
		if curPattern == `**` {
			if pnpi == len(pattern) {
				return true, nil
			}
			return false, wrapError(ErrInvalidPattern, `** must be at the end`)
		}
		if ok, err := matchPatternPart(curPattern, curNamePart); err != nil || !ok {
			return false, err
		}

		nsi = nnpi + 1
		psi = pnpi + 1
		if nsi >= len(name) && psi >= len(pattern) {
			return true, nil
		}
	}
}

func matchPatternPart(pattern, name string) (bool, error) {
	if pattern == `*` || pattern == `**` {
		return true, nil
	}
	if strings.HasPrefix(pattern, `%r{`) && strings.HasSuffix(pattern, `}`) {
		return regexp.MatchString(pattern[3:len(pattern)-1], name)
	}
	if strings.HasPrefix(pattern, `{`) && strings.HasSuffix(pattern, `}`) {
		parts := strings.Split(pattern[1:len(pattern)-1], `|`)
		for _, p := range parts {
			if p == name {
				return true, nil
			}
		}
	}
	return matchEqual(pattern, name), nil
}

func matchEqual(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if len(pattern) != len(name) {
		return false
	}
	// Check for ? in pattern
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '?' || pattern[i] == name[i] {
			continue
		}
		return false
	}
	return true
}

// checkPattern checks if the string matches any of the patterns
//
// Example:
// checkPattern(`test.it`, `test.*`) => true
// checkPattern(`test.it`, `test.*`, `test2`) => true
// checkPattern(`test.it.owner`, `test.*.*`, `test2.*`) => true
// checkPattern(`test.it.admin`, `test.*.owner`) => false
func checkPattern(name string, patterns ...string) bool {
	for _, pattern := range patterns {
		if ok, _ := MatchName(pattern, name); ok {
			return true
		}
	}
	return false
}

// checkResourcePattern checks if the resource name matches any of the patterns
//
// Example:
// checkResourcePattern(`test.Object`, `owner`, `*`) => true
// checkResourcePattern(`test.Object`, `register.owner`, `register.*`) => true
// checkResourcePattern(`test.Object`, `register.owner`, `test.Object.register.*`) => true
func checkResourcePattern(resName, name string, patterns ...string) bool {
	fullName := resName + `.` + name
	for _, pattern := range patterns {
		if ok, _ := MatchName(pattern, fullName); ok {
			return true
		}
		if ok, _ := MatchName(resName+`.`+pattern, fullName); ok {
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
