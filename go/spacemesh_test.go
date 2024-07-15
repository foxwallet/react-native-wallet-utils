package fox

import (
	"fmt"
	"testing"
)

func TestSpaceMeshSelfSpawnTx(t *testing.T) {
	tx := SpaceMeshSelfSpawnTx(/* your privateKey */"", "0", "1", "9eebff023abb17ccb775c602daade8ed708f0a50")
	fmt.Println(tx)
}
