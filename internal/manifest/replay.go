package manifest

// ReviewPacket records collection inputs and the depsound version used.
// Findings that cannot be collected again are listed as omissions.
type ReviewPacket struct {
	Schema      int              `json:"schema"`
	ToolVersion string           `json:"toolVersion"`
	Mode        string           `json:"mode"`
	Items       []ReviewItem     `json:"items,omitempty"`
	Omitted     []ReviewOmission `json:"omitted,omitempty"`
	Reason      string           `json:"reason,omitempty"`
}

// ReviewOmission identifies a finding to inspect in the saved report.
type ReviewOmission struct {
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}

// ReviewItem is data for bulk, never a shell command or a display reference.
type ReviewItem struct {
	Ecosystem  string      `json:"ecosystem,omitempty"`
	Name       string      `json:"name,omitempty"`
	From       string      `json:"from,omitempty"`
	To         string      `json:"to,omitempty"`
	Redirect   string      `json:"redirect,omitempty"`
	LockChange *LockChange `json:"lockChange,omitempty"`
}
