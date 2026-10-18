package report

import (
	_ "embed"
	"html/template"
	"io"
)

//go:embed report.html.tmpl
var htmlTemplate string

// SpecNames maps the specs that tests belong to to their titles for the HTML
// report.
var SpecNames = map[string]string{
	"gemSpec_IDP_Sek": "gematik Spezifikation Sektoraler Identity Provider",
	"gemSpec_IDP_FD":  "gematik Nutzungsspezifikation für Fachdienste",
}

func title(s *Summary) string {
	if s.Title != "" {
		return s.Title
	}
	return "Conformance report"
}

type htmlData struct {
	Summary   *Summary          `json:"summary"`
	Failed    bool              `json:"failed"`
	SpecNames map[string]string `json:"specNames"`
}

// HTML writes a self-contained HTML report (no external resources). All
// data, including untrusted server responses, is embedded as JSON and
// rendered as text by the page script.
func HTML(w io.Writer, s *Summary) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, struct {
		Title string
		Data  htmlData
	}{
		Title: title(s) + ": " + s.Target,
		Data:  htmlData{Summary: s, Failed: s.Failed(), SpecNames: SpecNames},
	})
}
