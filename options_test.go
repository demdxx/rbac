package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionError(t *testing.T) {
	assert.Error(t, WithChildRoles()(nil))
	assert.Error(t, WithPermissions()(nil))
	assert.Error(t, WithCustomCheck(nil)(nil))
	assert.Error(t, WithCustomCheck(func() {})(nil))
	assert.Error(t, WithCustomCheck(func() {}, []int{})(&SimplePermission{}))
	assert.Error(t, WithCustomCheck(func() {}, []int{})(&ResourcePermission{}))
}
