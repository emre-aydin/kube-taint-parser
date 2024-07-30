/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package taints

import (
	"reflect"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
)

func TestParseTaints(t *testing.T) {
	cases := []struct {
		name                   string
		spec                   []string
		expectedTaints         []v1.Taint
		expectedTaintsToRemove []v1.Taint
		expectedErr            bool
	}{
		{
			name:        "invalid empty spec format",
			spec:        []string{""},
			expectedErr: true,
		},
		// taint spec format without the suffix '-' must be either '<key>=<value>:<effect>', '<key>:<effect>', or '<key>'
		{
			name:        "invalid spec format without effect",
			spec:        []string{"foo=abc"},
			expectedErr: true,
		},
		{
			name:        "invalid spec format with multiple '=' separators",
			spec:        []string{"foo=abc=xyz:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec format with multiple ':' separators",
			spec:        []string{"foo=abc:xyz:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value without separator",
			spec:        []string{"foo"},
			expectedErr: true,
		},
		// taint spec must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character.
		{
			name:        "invalid spec taint value with special chars '%^@'",
			spec:        []string{"foo=nospecialchars%^@:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value with non-alphanumeric characters",
			spec:        []string{"foo=Tama-nui-te-rā.is.Māori.sun:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value with special chars '\\'",
			spec:        []string{"foo=\\backslashes\\are\\bad:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value with start with an non-alphanumeric character '-'",
			spec:        []string{"foo=-starts-with-dash:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value with end with an non-alphanumeric character '-'",
			spec:        []string{"foo=ends-with-dash-:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value with start with an non-alphanumeric character '.'",
			spec:        []string{"foo=.starts.with.dot:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value with end with an non-alphanumeric character '.'",
			spec:        []string{"foo=ends.with.dot.:NoSchedule"},
			expectedErr: true,
		},
		// The value range of taint effect is "NoSchedule", "PreferNoSchedule", "NoExecute"
		{
			name:        "invalid spec effect for adding taint",
			spec:        []string{"foo=abc:invalid_effect"},
			expectedErr: true,
		},
		{
			name:        "invalid spec effect for deleting taint",
			spec:        []string{"foo:invalid_effect-"},
			expectedErr: true,
		},
		{
			name:        "duplicated taints with the same key and effect",
			spec:        []string{"foo=abc:NoSchedule", "foo=abc:NoSchedule"},
			expectedErr: true,
		},
		{
			name:        "invalid spec taint value exceeding the limit",
			spec:        []string{strings.Repeat("a", 64)},
			expectedErr: true,
		},
		{
			name: "add new taints with no special chars",
			spec: []string{"foo=abc:NoSchedule", "bar=abc:NoSchedule", "baz:NoSchedule", "qux:NoSchedule", "foobar=:NoSchedule"},
			expectedTaints: []v1.Taint{
				{
					Key:    "foo",
					Value:  "abc",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "bar",
					Value:  "abc",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "baz",
					Value:  "",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "qux",
					Value:  "",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "foobar",
					Value:  "",
					Effect: v1.TaintEffectNoSchedule,
				},
			},
			expectedErr: false,
		},
		{
			name: "delete taints with no special chars",
			spec: []string{"foo:NoSchedule-", "bar:NoSchedule-", "qux=:NoSchedule-", "dedicated-"},
			expectedTaintsToRemove: []v1.Taint{
				{
					Key:    "foo",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "bar",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "qux",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key: "dedicated",
				},
			},
			expectedErr: false,
		},
		{
			name: "add taints and delete taints with no special chars",
			spec: []string{"foo=abc:NoSchedule", "bar=abc:NoSchedule", "baz:NoSchedule", "qux:NoSchedule", "foobar=:NoSchedule", "foo:NoSchedule-", "bar:NoSchedule-", "baz=:NoSchedule-"},
			expectedTaints: []v1.Taint{
				{
					Key:    "foo",
					Value:  "abc",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "bar",
					Value:  "abc",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "baz",
					Value:  "",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "qux",
					Value:  "",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "foobar",
					Value:  "",
					Effect: v1.TaintEffectNoSchedule,
				},
			},
			expectedTaintsToRemove: []v1.Taint{
				{
					Key:    "foo",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "bar",
					Effect: v1.TaintEffectNoSchedule,
				},
				{
					Key:    "baz",
					Value:  "",
					Effect: v1.TaintEffectNoSchedule,
				},
			},
			expectedErr: false,
		},
	}

	for _, c := range cases {
		taints, taintsToRemove, err := ParseTaints(c.spec)
		if c.expectedErr && err == nil {
			t.Errorf("[%s] expected error for spec %s, but got nothing", c.name, c.spec)
		}
		if !c.expectedErr && err != nil {
			t.Errorf("[%s] expected no error for spec %s, but got: %v", c.name, c.spec, err)
		}
		if !reflect.DeepEqual(c.expectedTaints, taints) {
			t.Errorf("[%s] expected returen taints as %v, but got: %v", c.name, c.expectedTaints, taints)
		}
		if !reflect.DeepEqual(c.expectedTaintsToRemove, taintsToRemove) {
			t.Errorf("[%s] expected return taints to be removed as %v, but got: %v", c.name, c.expectedTaintsToRemove, taintsToRemove)
		}
	}
}
