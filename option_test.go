package cert4now

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFilterNotEmptyString(t *testing.T) {
	cases := []struct {
		In   []string
		Want []string
	}{
		{},
		{[]string{""}, []string{}},
		{[]string{"", "a", ""}, []string{"a"}},
		{[]string{"", "a", "b", ""}, []string{"a", "b"}},
		{[]string{"", "a", "", "b", ""}, []string{"a", "b"}},
		{[]string{"", "a", "", "b", "c", ""}, []string{"a", "b", "c"}},
		{[]string{"", "a", "", "b", "", "c", ""}, []string{"a", "b", "c"}},
		{[]string{"", "a", "", "", "b", "", "c", ""}, []string{"a", "b", "c"}},
		{[]string{"a"}, []string{"a"}},
		{[]string{"a", "b"}, []string{"a", "b"}},
		{[]string{"a", "", "b"}, []string{"a", "b"}},
		{[]string{"a", "", "", "b"}, []string{"a", "b"}},
	}
	for i, c := range cases {
		got := filterNonEmptyString(append([]string(nil), c.In...))
		if diff := cmp.Diff(c.Want, got); len(diff) > 0 {
			t.Errorf("[%d] -want +got\n%s", i, diff)
		}
	}
}
