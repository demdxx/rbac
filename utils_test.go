package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPatternPermissionNameCheck(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		expected bool
	}{
		{name: `test`, patterns: []string{`test`}, expected: true},
		{name: `test`, patterns: []string{`test`, `test2`}, expected: true},
		{name: `test.it`, patterns: []string{`test.*`}, expected: true},
		{name: `test.it`, patterns: []string{`test.*`, `test2`}, expected: true},
		{name: `test.it.owner`, patterns: []string{`test.*.*`, `test2.*`}, expected: true},
		{name: `test.it.admin`, patterns: []string{`test.*.owner`}, expected: false},
		{name: `test.it.admin`, patterns: []string{`test.permission.*`}, expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, checkPattern(test.name, test.patterns...))
		})
	}
}

type testResource struct {
	name string
}

func (r *testResource) RBACResourceName() string { return `rbac.testResource` }

func TestResourceNameExtractor(t *testing.T) {
	tests := []struct {
		name     string
		resource any
		expected string
	}{
		{name: `nil`, resource: nil, expected: ``},
		{name: `string`, resource: `test`, expected: ``},
		{name: `struct`, resource: testObject{}, expected: `rbac.testObject`},
		{name: `struct pointer`, resource: &testObject{}, expected: `rbac.testObject`},
		{name: `struct pointer`, resource: &testExt{}, expected: `rbac.testExt`},
		{name: `struct pointer`, resource: &testExt{name: `test`}, expected: `rbac.testExt`},
		{name: `struct custom name`, resource: &testResource{name: `test`}, expected: `rbac.testResource`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, GetResName(test.resource))
		})
	}
}
