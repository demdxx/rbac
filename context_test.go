package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContextExtData(t *testing.T) {
	val := map[string]interface{}{"test": "value"}
	ctx := context.TODO()
	ctx = withExtData(ctx, val)
	assert.Equal(t, val, ExtData(ctx))
}
