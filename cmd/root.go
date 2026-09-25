package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/gocolly/colly/v2"
	"github.com/spf13/cobra"

	"gitlab.com/bboycode/jsmap/internal"
)

// Flag-backed variables. Cobra populates these when the command runs.
var (
	targetURL   string
	rulesPath   string
	concurrency int
)

var rootCmd = &cobra.Command{
	Use:   "jsmap",
	Short: "Crawl a web page's JS and scan it for leaked secrets and endpoints",
	Long: `jsmap visits a target URL, collects every <script> it
finds (inline and external), and scans the JS content against a
gitleaks-style rule set for secrets and interesting links.`,
	RunE: runScan,
}

// Execute is called by main.go — the single entrypoint into the CLI.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target URL to scan (required)")
	rootCmd.Flags().StringVarP(&rulesPath, "rules", "r", "templates/js-secrets.toml", "Path to rules TOML file")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 5, "Number of concurrent script fetches")

	rootCmd.MarkFlagRequired("url")
}

func runScan(_ *cobra.Command, _ []string) error {
	rules, err := internal.LoadRules(rulesPath)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	fmt.Printf("Loaded %d rules\n", len(rules))

	c := colly.NewCollector()
	var scriptURLs []string
	var allFindings []internal.Finding
	var mu sync.Mutex

	c.OnHTML("script:not([src])", func(e *colly.HTMLElement) {
		if e.Text == "" {
			return
		}
		findings := internal.Scan(e.Text, "inline", rules)
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	})

	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		scriptURLs = append(scriptURLs, e.Request.AbsoluteURL(e.Attr("src")))
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting:", r.URL.String())
	})

	if err := c.Visit(targetURL); err != nil {
		return fmt.Errorf("visiting target: %w", err)
	}

	fmt.Printf("Found %d external scripts, fetching with concurrency=%d...\n", len(scriptURLs), concurrency)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, url := range scriptURLs {
		wg.Add(1)
		sem <- struct{}{}

		go func(scriptURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			content, err := fetchJS(scriptURL)
			if err != nil {
				fmt.Println("Failed to fetch:", scriptURL, "-", err)
				return
			}

			findings := internal.Scan(content, scriptURL, rules)

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(url)
	}

	wg.Wait()

	secrets := internal.Dedupe(internal.FilterByTag(allFindings, "secret"))
	links := internal.Dedupe(internal.FilterByTag(allFindings, "link"))

	fmt.Printf("\n=== Secrets (%d) ===\n", len(secrets))
	for _, f := range secrets {
		fmt.Printf("[%s] %s\n  -> %s\n\n", f.RuleID, f.Source, f.Match)
	}

	fmt.Printf("=== Links (%d) ===\n", len(links))
	for _, f := range links {
		fmt.Printf("[%s] %s\n  -> %s\n\n", f.RuleID, f.Source, f.Match)
	}

	return nil
}

func fetchJS(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
