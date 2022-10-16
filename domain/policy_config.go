package domain

type PolicyTargetApplication struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type PolicyTargetResource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type PolicyConfigTarget struct {
	Namespaces   []string                  `json:"namespaces,omitempty"`
	Applications []PolicyTargetApplication `json:"apps,omitempty"`
	Resources    []PolicyTargetResource    `json:"resources,omitempty"`
}

type PolicyConfigParameter struct {
	Value     interface{}
	ConfigRef string
}

type PolicyConfigConfig struct {
	Parameters map[string]PolicyConfigParameter `json:"parameters"`
}

// PolicyConfig represents a policy config
type PolicyConfig struct {
	Config map[string]PolicyConfigConfig `json:"config"`
	Match  PolicyConfigTarget            `json:"match"`
}
