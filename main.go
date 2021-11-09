package main

import (
	_ "embed"
	"flag"
	"fmt"
	"github.com/owenrumney/go-sarif/sarif"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
)

//go:embed settings.yaml
var defaultConfig []byte

func HumanWrite(report *sarif.Report, w io.Writer) {

	for _, r := range report.Runs {
		for _, result := range r.Results {
			for _, location := range result.Locations {

				fmt.Fprintf(w,
					"%s - %s ==> %s ==> %s\n",
					*result.RuleID,
					*result.Message.Text,
					*location.PhysicalLocation.ArtifactLocation.URI,
					*location.PhysicalLocation.Region.Snippet.Text,
				)

				for _, a := range result.Message.Arguments {
					fmt.Fprintf(w, "*****\n%s\n*****\n\n", a)

				}
			}
		}
	}
}

func createResult(c *Context, data string) *sarif.Result {

	physical := sarif.NewPhysicalLocation()
	physical.ArtifactLocation = sarif.NewSimpleArtifactLocation(c.Path)
	physical.Region = sarif.NewRegion()
	line := 0
	physical.Region.StartLine = &line

	physical.Region.Snippet = sarif.NewArtifactContent()
	physical.Region.Snippet.Text = &data

	location := sarif.NewLocationWithPhysicalLocation(physical)

	propertyBag := sarif.NewPropertyBag()
	if c.Rule.Severity != "" {
		propertyBag.AddString("severity", c.Rule.Severity)
	}

	if c.Rule.Url != "" {
		propertyBag.AddString("rule_url", c.Rule.Url)
	}

	propertyBag.Add("tags", c.Rule.Tags)

	result := sarif.Result{
		RuleID: &c.Rule.Name,
		Message: sarif.Message{
			Text: &c.Rule.Description,
		},
		Locations: []*sarif.Location{location},
	}
	result.AttachPropertyBag(propertyBag)

	return &result
}

type Conf struct {
	Rules map[string]Rule `yaml:"rules"`
}

type Rule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Url         string   `yaml:"url"`
	Tags        []string `yaml:"tags"`
	Files       []string `yaml:"files"`
	Match       []string `yaml:"match"`
	Includes    []string `yaml:"includes"`
	Excludes    []string `yaml:"excludes"`
	rFiles      []*regexp.Regexp
	rIncludes   []*regexp.Regexp
	rExcludes   []*regexp.Regexp
	rMatch      []*regexp.Regexp
}

type Context struct {
	Path      string
	InputData []byte
	Rule      Rule
	Results   *[]*sarif.Result
}

func main() {
	generateSettings := flag.Bool("generate-settings", false, "generates default settings.yaml in current directory")
	settingsfile := flag.String("settings", "./settings.yaml", "Settings file")
	humanize := flag.Bool("human", false, "Allows humans to use the tool")
	output := flag.String("output", "", "Output file")

	flag.Parse()

	if *generateSettings {
		fmt.Println(string(defaultConfig))
		os.Exit(0)
	}

	var outFile io.Writer = os.Stdout

	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Println("Cannot open output file")
		}
		outFile = f
	}

	report, err := sarif.New(sarif.Version210)
	run := sarif.NewRun("regex-scanner", "")
	report.AddRun(run)

	conf, err := getConfig(err, settingsfile)

	for _, rule := range conf.Rules {

		rule.rFiles = compileRegexes(rule.Files)
		rule.rIncludes = compileRegexes(rule.Includes)
		rule.rExcludes = compileRegexes(rule.Excludes)
		rule.rMatch = compileRegexes(rule.Match)

		file_path, err := os.Getwd()
		if err != nil {
			fmt.Fprint(os.Stderr, "ERROR: Unable to get working directory\n")
			os.Exit(-1)
		}

		if fp := flag.Arg(0); fp != "" {
			file_path = fp
		}

		err = filepath.Walk(file_path,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				matches := matchesAny(path, rule.rFiles)
				if !matches {
					return nil
				}

				inputData, err := ioutil.ReadFile(path)

				ctx := Context{
					Path:      path,
					InputData: inputData,
					Rule:      rule,
					Results:   &run.Results,
				}

				for _, r := range rule.rMatch {
					matches := r.FindAllSubmatch(inputData, -1)

					for _, match := range matches {
						searchString := ""
						if len(match) == 1 {
							searchString = string(match[0])
						} else if len(match) > 1 {
							searchString = string(match[1])
						}

						if len(rule.rIncludes) > 0 {
							matches := matchesAny(searchString, rule.rIncludes)
							if !matches {
								continue
							}

						}

						if len(rule.rExcludes) > 0 {
							matches := matchesAny(searchString, rule.rExcludes)
							if matches {
								continue
							}
						}

						run.Results = append(run.Results, createResult(&ctx, searchString))
					}
				}

				return nil
			})

		if err != nil {
			os.Exit(-1)
		}
	}

	if *humanize {
		HumanWrite(report, outFile)
	} else {
		_ = report.PrettyWrite(outFile)
	}
}

func matchesAny(data string, regexes []*regexp.Regexp) bool {
	fileValid := false
	for _, r := range regexes {
		fileValid = fileValid || r.MatchString(data)
	}

	return fileValid
}

func compileRegexes(regexes []string) []*regexp.Regexp {
	var out []*regexp.Regexp

	for _, fileRegex := range regexes {
		regex, err := regexp.Compile(fileRegex)
		if err == nil {
			out = append(out, regex)
		}
	}
	return out
}

func getConfig(err error, settingsfile *string) (Conf, error) {
	conf := Conf{}

	yamlFile, err := ioutil.ReadFile(*settingsfile)
	if err != nil {
		yamlFile = defaultConfig
	}

	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return conf, err
}
