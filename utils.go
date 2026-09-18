package rbac

import (
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/demdxx/xtypes"
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

// PermissionPatternExpander optionally expands check patterns using object knowledge.
// Original patterns are always kept; returned values are appended.
type PermissionPatternExpander interface {
	RBACPermissionPatterns(patterns ...string) []string
}

// ExpandPermissionPatterns resolves check patterns from a resource.
//
// Rules:
//  1. Always keep the original patterns (manual names stay valid).
//  2. If resource implements PermissionPatternExpander, append its extra patterns.
//  3. Otherwise if GetResName(resource) is not empty, append resName+"."+pattern
//     for each pattern that does not already have that prefix.
//  4. nil resource or empty name: originals only.
func ExpandPermissionPatterns(resource any, patterns ...string) []string {
	if len(patterns) == 0 {
		return patterns
	}
	out := append([]string{}, patterns...)
	if resource == nil {
		return out
	}
	if expander, ok := resource.(PermissionPatternExpander); ok {
		return appendUniqueStrings(out, expander.RBACPermissionPatterns(patterns...)...)
	}
	name := GetResName(resource)
	if name == `` {
		return out
	}
	prefix := name + `.`
	extra := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern == `` || strings.HasPrefix(pattern, prefix) {
			continue
		}
		extra = append(extra, prefix+pattern)
	}
	return appendUniqueStrings(out, extra...)
}

func appendUniqueStrings(dst []string, extra ...string) []string {
	if len(extra) == 0 {
		return dst
	}
	seen := make(map[string]struct{}, len(dst)+len(extra))
	for _, s := range dst {
		seen[s] = struct{}{}
	}
	for _, s := range extra {
		if s == `` {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		dst = append(dst, s)
	}
	return dst
}

func uniquePermissions(perms []Permission) []Permission {
	if len(perms) < 2 {
		return perms
	}
	seen := make(map[string]struct{}, len(perms))
	out := make([]Permission, 0, len(perms))
	for _, p := range perms {
		if p == nil {
			continue
		}
		name := p.Name()
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, p)
	}
	return out
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
	for res.Kind() == reflect.Interface || res.Kind() == reflect.Pointer {
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

// Included returns true if testRole is included in the base role or equal
func Included(base Role, testRole Role) bool {
	if base == nil || testRole == nil {
		return false
	}
	if base.Name() == testRole.Name() {
		return true
	}
	basePermissions := xtypes.Slice[Permission](base.Permissions()).
		Sort(func(a, b Permission) bool { return a.Name() < b.Name() })
	testPermissions := xtypes.Slice[Permission](testRole.Permissions()).
		Sort(func(a, b Permission) bool { return a.Name() < b.Name() })
	if len(basePermissions) < len(testPermissions) {
		return false
	}
	j := 0
	for _, perm := range basePermissions {
		if testPermissions[j].Name() != perm.Name() {
			continue
		}
		if j = j + 1; j >= len(testPermissions) {
			return true
		}
	}
	return false
}
