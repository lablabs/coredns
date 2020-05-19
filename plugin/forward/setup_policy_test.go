package forward

import (
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy"
)

func TestSetupPolicy(t *testing.T) {
	tests := []struct {
		input          string
		shouldErr      bool
		expectedPolicy string
		expectedErr    string
	}{
		// positive
		{"forward . 127.0.0.1 {\npolicy random\n}\n", false, "random", ""},
		{"forward . 127.0.0.1 {\npolicy round_robin\n}\n", false, "round_robin", ""},
		{"forward . 127.0.0.1 {\npolicy sequential\n}\n", false, "sequential", ""},
		// negative
		{"forward . 127.0.0.1 {\npolicy random2\n}\n", true, "random", "unknown policy"},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		f, err := parseForward(c)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: expected error but found %s for input %s", i, err, test.input)
		}

		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: expected no error but found one for input %s, got: %v", i, test.input, err)
			}

			if !strings.Contains(err.Error(), test.expectedErr) {
				t.Errorf("Test %d: expected error to contain: %v, found error: %v, input: %s", i, test.expectedErr, err, test.input)
			}
		}

		if !test.shouldErr && f.p.String() != test.expectedPolicy {
			t.Errorf("Test %d: expected: %s, got: %s", i, test.expectedPolicy, f.p.String())
		}
	}
}

func TestSetupPolicySelection(t *testing.T) {
	tests := []struct {
		input         string
		shouldErr     bool
		expectedOrder []string
		expectedErr   string
	}{
		{"forward . 1.1.1.1 {\npolicy sequential \n}\n", false, []string{"1.1.1.1:53"}, ""},
		{"forward . 1.1.1.1 {\npolicy random\n}\n", false, []string{"1.1.1.1:53"}, ""},
		{"forward . 1.1.1.1 {\npolicy round_robin\n}\n", false, []string{"1.1.1.1:53"}, ""},
		{"forward . 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 {\npolicy sequential\n}\n", false, []string{"1.1.1.1:53", "2.2.2.2:53", "3.3.3.3:53", "4.4.4.4:53"}, ""},
		{"forward . 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 {\npolicy round_robin\n}\n", false, []string{"2.2.2.2:53", "1.1.1.1:53", "3.3.3.3:53", "4.4.4.4:53"}, ""},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		f, err := parseForward(c)

		orderedProxies := f.List()
		var orderedProxiesString []string
		for _, p := range orderedProxies {
			orderedProxiesString = append(orderedProxiesString, p.addr)
		}

		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: expected no error but found one for input %s, got: %v", i, test.input, err)
			}
		}

		if !test.shouldErr && !reflect.DeepEqual(orderedProxiesString, test.expectedOrder) {
			t.Errorf("Test %d: expected: %v, got: %v", i, test.expectedOrder, orderedProxiesString)
		}
	}
}
