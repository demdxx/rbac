package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContextExtData(t *testing.T) {
	val := map[string]any{"test": "value"}
	ctx := context.TODO()
	ctx = withExtData(ctx, val)
	ctx = withExtData(ctx, nil)
	assert.Equal(t, val, ExtData(ctx))
}
