package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	ociManifest    = "application/vnd.oci.image.manifest.v1+json"
	dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	ociIndex       = "application/vnd.oci.image.index.v1+json"
	dockerIndex    = "application/vnd.docker.distribution.manifest.list.v2+json"
	ociConfig      = "application/vnd.oci.image.config.v1+json"
	dockerConfig   = "application/vnd.docker.container.image.v1+json"
	ociGzip        = "application/vnd.oci.image.layer.v1.tar+gzip"
	dockerGzip     = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform,omitempty"`
}

type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

type ImageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type Reference struct{ Repository, Tag string }

func (r Reference) String() string { return r.Repository + ":" + r.Tag }

// This lab accepts Docker Hub repository[:tag] references, not registry URLs.
func ParseReference(value string) (Reference, error) {
	value = strings.TrimPrefix(value, "docker.io/")
	name, tag := value, "latest"
	if i := strings.LastIndex(value, ":"); i >= 0 {
		name, tag = value[:i], value[i+1:]
	}
	part := regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	pieces := strings.Split(name, "/")
	if len(pieces) < 1 || len(pieces) > 2 || len(name) > 200 {
		return Reference{}, fmt.Errorf("use a Docker Hub repository[:tag]")
	}
	for _, p := range pieces {
		if !part.MatchString(p) {
			return Reference{}, fmt.Errorf("invalid repository: %q", name)
		}
	}
	if len(pieces) == 1 {
		name = "library/" + name
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`).MatchString(tag) {
		return Reference{}, fmt.Errorf("invalid tag: %q", tag)
	}
	return Reference{name, tag}, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil && value == strings.ToLower(value)
}

func checkDescriptor(d Descriptor) error {
	if !validDigest(d.Digest) || d.Size <= 0 {
		return fmt.Errorf("invalid descriptor: %q, size %d", d.Digest, d.Size)
	}
	return nil
}

func parseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.SchemaVersion != 2 || (m.MediaType != ociManifest && m.MediaType != dockerManifest) {
		return nil, fmt.Errorf("unsupported image manifest: %q", m.MediaType)
	}
	if len(m.Layers) == 0 || len(m.Layers) > 64 {
		return nil, fmt.Errorf("this lab accepts images with 1 to 64 layers")
	}
	if m.Config.MediaType != ociConfig && m.Config.MediaType != dockerConfig {
		return nil, fmt.Errorf("unsupported image config: %q", m.Config.MediaType)
	}
	if err := checkDescriptor(m.Config); err != nil {
		return nil, err
	}
	for _, d := range m.Layers {
		if err := checkDescriptor(d); err != nil {
			return nil, err
		}
		if d.MediaType != ociGzip && d.MediaType != dockerGzip {
			return nil, fmt.Errorf("unsupported layer media type: %s; this lab uses gzip layers", d.MediaType)
		}
	}
	return &m, nil
}

func parseConfig(data []byte, m *Manifest) (*ImageConfig, error) {
	var c ImageConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.OS != "linux" || c.Architecture != "amd64" || c.RootFS.Type != "layers" {
		return nil, fmt.Errorf("this lab requires a linux/amd64 image with filesystem layers")
	}
	if len(c.RootFS.DiffIDs) != len(m.Layers) {
		return nil, fmt.Errorf("layer / diff_id count mismatch")
	}
	for _, id := range c.RootFS.DiffIDs {
		if !validDigest(id) {
			return nil, fmt.Errorf("invalid diff_id: %q", id)
		}
	}
	return &c, nil
}
