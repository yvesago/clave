package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPIN(t *testing.T) {
	tests := map[string]bool{
		"123456": false,
		"111111": false,
		"222222": false,
		"127456": true,
		"458354": true,
	}

	for val, res := range tests {
		assert.Equal(t, res, validPIN(val), val+" test")
	}
}
