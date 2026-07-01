// Command titleclass is a manual smoke-test tool for the
// github.com/praetorian-inc/brutus/pkg/enum/titleclass package. It classifies
// job titles into departments, either one title via --title or many piped on
// stdin (one per line), and can print the full probability distribution.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/praetorian-inc/brutus/pkg/enum/titleclass"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "titleclass:", err)
		os.Exit(1)
	}
}

func run() error {
	title := flag.String("title", "", "classify a single title (default: read titles from stdin, one per line)")
	threshold := flag.Float64("threshold", -1, "confidence threshold (default: the model's DefaultThreshold)")
	verbose := flag.Bool("verbose", false, "print the full probability distribution, sorted descending")
	flag.Parse()

	clf, err := titleclass.Default()
	if err != nil {
		return fmt.Errorf("loading classifier: %w", err)
	}

	th := *threshold
	if th < 0 {
		th = clf.DefaultThreshold()
	}

	if *title != "" {
		printResult(clf.ClassifyWithThreshold(*title, th), *verbose)
		return nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		printResult(clf.ClassifyWithThreshold(line, th), *verbose)
	}
	return scanner.Err()
}

func printResult(res titleclass.Result, verbose bool) {
	if verbose {
		fmt.Println(res.Title)
	}
	fmt.Printf("%s  (confidence %.3f)\n", res.Department, res.Confidence)
	if verbose {
		printDistribution(res.Probabilities)
	}
}

func printDistribution(probs map[string]float64) {
	labels := make([]string, 0, len(probs))
	for label := range probs {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool {
		return probs[labels[i]] > probs[labels[j]]
	})
	for _, label := range labels {
		fmt.Printf("%s  %.3f\n", label, probs[label])
	}
}
