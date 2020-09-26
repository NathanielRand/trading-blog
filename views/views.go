package views

import "html/template"

// NewView function to make it easier to create views.
func NewView(layout string, files ...string) *View {
	// Append common template files to the list of files provided.
	files = append(
		files, 
		"views/layouts/footer.html",
		"views/layouts/materialize.html")
	
	t, err := template.ParseFiles(files...)
	if err != nil {
		panic(err)
	}
	
	return &View{
		Template: t,
		Layout: layout,
	}
}

type View struct {
	Template *template.Template
	Layout string
}