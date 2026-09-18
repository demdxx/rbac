package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDummyCheck(t *testing.T) {
	perm := NewDummyPermission(`test`, true)
	assert.Equal(t, `test`, perm.Name())
	assert.True(t, perm.CheckPermissions(context.TODO(), nil, `view`))
	assert.NotNil(t, perm.CheckedPermissions(context.TODO(), nil, `view`))

	denied := NewDummyPermission(`deny`, false)
	assert.False(t, denied.CheckPermissions(context.TODO(), nil, `view`))
	assert.Nil(t, denied.CheckedPermissions(context.TODO(), nil, `view`))
}
