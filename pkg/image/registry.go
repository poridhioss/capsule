package image

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	base, token, repository string
	http                    *http.Client
}

func NewClient(repository string) (*Client, error) {
	c := &Client{
		base: "https://registry-1.docker.io", repository: repository,
		http: &http.Client{Timeout: 5 * time.Minute},
	}
	resp, err := c.http.Get(c.base + "/v2/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return nil, responseError(resp)
	}
	if err := c.authenticate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Docker Hub's anonymous token service; no username or password is stored.
func (c *Client) authenticate() error {
	query := url.Values{"service": {"registry.docker.io"}, "scope": {"repository:" + c.repository + ":pull"}}
	resp, err := c.http.Get("https://auth.docker.io/token?" + query.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return responseError(resp)
	}
	var reply struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&reply); err != nil {
		return err
	}
	c.token = reply.Token
	if c.token == "" {
		c.token = reply.AccessToken
	}
	if c.token == "" {
		return fmt.Errorf("token service returned no token")
	}
	return nil
}

func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("registry HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
}

func (c *Client) get(endpoint, accept string) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodGet, c.base+endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", accept)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			if err := c.authenticate(); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			err := responseError(resp)
			resp.Body.Close()
			return nil, err
		}
		return resp, nil
	}
	return nil, fmt.Errorf("registry authentication failed")
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("JSON response exceeds %d bytes", max)
	}
	return b, err
}

func (c *Client) manifestBytes(ref string) ([]byte, error) {
	accept := strings.Join([]string{ociManifest, dockerManifest, ociIndex, dockerIndex}, ", ")
	resp, err := c.get("/v2/"+c.repository+"/manifests/"+ref, accept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := readLimited(resp.Body, 8<<20)
	if err != nil {
		return nil, err
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != "" && got != digest(data) {
		return nil, fmt.Errorf("manifest response digest mismatch")
	}
	return data, nil
}

// Resolve an optional index, then retain the exact platform-manifest bytes.
func (c *Client) FetchManifest(ref string) (*Manifest, []byte, error) {
	data, err := c.manifestBytes(ref)
	if err != nil {
		return nil, nil, err
	}
	var index struct {
		MediaType string       `json:"mediaType"`
		Manifests []Descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, nil, err
	}
	if index.MediaType == ociIndex || index.MediaType == dockerIndex {
		var selected *Descriptor
		for i, d := range index.Manifests {
			if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == "amd64" &&
				(d.Platform.Variant == "" || d.Platform.Variant == "v1") {
				selected = &index.Manifests[i]
				break
			}
		}
		if selected == nil {
			return nil, nil, fmt.Errorf("no linux/amd64 manifest in image index")
		}
		if err := checkDescriptor(*selected); err != nil {
			return nil, nil, err
		}
		data, err = c.manifestBytes(selected.Digest)
		if err != nil {
			return nil, nil, err
		}
		if digest(data) != selected.Digest || int64(len(data)) != selected.Size {
			return nil, nil, fmt.Errorf("platform-manifest descriptor mismatch")
		}
	}
	m, err := parseManifest(data)
	return m, data, err
}

func (c *Client) BlobReader(id string) (io.ReadCloser, error) {
	if !validDigest(id) {
		return nil, fmt.Errorf("invalid blob digest")
	}
	resp, err := c.get("/v2/"+c.repository+"/blobs/"+id, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (c *Client) ConfigBytes(d Descriptor) ([]byte, error) {
	r, err := c.BlobReader(d.Digest)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := readLimited(r, 8<<20)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != d.Size || digest(b) != d.Digest {
		return nil, fmt.Errorf("config digest or size mismatch")
	}
	return b, nil
}
