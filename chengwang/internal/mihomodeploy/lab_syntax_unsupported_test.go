//go:build !linux

package mihomodeploy

import (
	"context"
	"testing"
)
func TestLabSyntaxUnsupportedNeverExecutesOrReturnsSuccess(t *testing.T){if _,err:=labServiceSyntax(context.Background(),nil,nil,nil,"");err==nil{t.Fatal("unsupported syntax succeeded")}}
