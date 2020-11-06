package views

import (
	"html/template"
	"net/http"
	"path/filepath"
	"bytes"
	"io"
)

var (
	LayoutDir   string = "views/layouts/"
	TemplateDir string = "views/"
	TemplateExt string = ".html"
)

func NewView(layout string, files ...string) *View {
	addTemplatePath(files)
	addTemplateExt(files)

	files = append(files, layoutFiles()...)
	t, err := template.ParseFiles(files...)
	if err != nil {
		panic(err)
	}

	return &View{
		Template: t,
		Layout:   layout,
	}
}

type View struct {
	Template *template.Template
	Layout   string
}

func (v *View) Render(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "text/html")
	//	Check the underlying type of any data
	//	passed into our Render method using a type switch.
	switch data.(type) {
	//  If it is of the Data type we don’t need to do anything.
	//  That is what our views expect, so we can leave the data along.
	case Data:
		//	Do nothing
	//	If the data is any other type we know that it
	//	isn’t in the format our views expect. One way
	//	to handle this might be to return an error,
	//	but in our case we are instead going to wrap it
	//	inside of a new Data object, setting this
	//	data to the Yield field.
	default:
		data = Data{
			Yield: data,
		}
	}
	// Use the buffer as a temporary location to execute 
	// our templates into. Once we have confirmed that 
	// there weren’t any errors executing the template we 
	// will have the entire executed template stored 
	// inside of our Buffer, and we can copy it over 
	// to the ResponseWriter.
	// We are using a buffer because writing any data 
	// to ResponseWriter will result in a 200 status 
	// code and we can’t undo that write. By writing 
	// to a buffer first we can confirm that the 
	// entire template executes before we start 
	// writing any data to the ResponseWriter.
	var buf bytes.Buffer
	err := v.Template.ExecuteTemplate(&buf, v.Layout, data)
	if err != nil {
		http.Error(w, "Something went wrong. If the problem " +
				  "persists, please contact support.", 
				  http.StatusInternalServerError)
		return
	}
	io.Copy(w, &buf)
}

func (v *View) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.Render(w, nil)
}

// addTemplatePath takes in a slice of strings
// representing file paths for templates, and it prepends
// the TemplateDir directory to each string in the slice
//
// Eg the input {"home"} would result in the output
// {"views/home"} if TemplateDir == "views/"
func addTemplatePath(files []string) {
	for i, f := range files {
		files[i] = TemplateDir + f
	}
}

// addTemplateExt takes in a slice of strings
// representing file paths for templates and it appends
// the TemplateExt extension to each string in the slice
//
// Eg the input {"home"} would result in the output
// {"home.gohtml"} if TemplateExt == ".gohtml"
func addTemplateExt(files []string) {
	for i, f := range files {
		files[i] = f + TemplateExt
	}
}

func layoutFiles() []string {
	files, err := filepath.Glob(LayoutDir + "*" + TemplateExt)
	if err != nil {
		panic(err)
	}
	return files
}
