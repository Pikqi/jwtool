package internal

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

type SendOpts struct {
	CookieName string // ako je setovano, token se salje kao cookie, a ne kao bearer header
	Keyword    string // ako je setovano, body mora sadrzati ovaj keyword da bi se vratilo success
}

type AttackResult struct {
	StatusCode int
	Body       string
	Success    bool
	Reason     string // razlog za success/fail
}

func SendWithJWT(url, token string, opts SendOpts) (AttackResult, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				for _, cookie := range via[0].Cookies() {
					req.AddCookie(cookie)
				}
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return AttackResult{}, fmt.Errorf("Failed to build request: %w", err)
	}

	if opts.CookieName != "" {
		req.AddCookie(&http.Cookie{Name: opts.CookieName, Value: token})
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return AttackResult{}, fmt.Errorf("Request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return AttackResult{}, fmt.Errorf("Failed to read response: %w", err)
	}
	body := string(bodyBytes)

	result := AttackResult{
		StatusCode: resp.StatusCode,
		Body:       body,
	}

	if opts.Keyword != "" {
		if strings.Contains(body, opts.Keyword) {
			result.Success = true
			result.Reason = fmt.Sprintf("Keyword %q found in body", opts.Keyword)
		} else {
			result.Success = false
			result.Reason = fmt.Sprintf("Keyword %q not found in body", opts.Keyword)
		}
	} else {
		// nema keyword, vraca status code
		result.Success = resp.StatusCode == http.StatusOK
		result.Reason = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return result, nil

}
