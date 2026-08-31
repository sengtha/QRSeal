# Single column (canonical) and two column, from one source.
.PHONY: all onecol twocol clean

all: onecol twocol

onecol:
	pdflatex -interaction=nonstopmode -halt-on-error main.tex >/dev/null
	bibtex main >/dev/null
	pdflatex -interaction=nonstopmode -halt-on-error main.tex >/dev/null
	pdflatex -interaction=nonstopmode -halt-on-error main.tex >/dev/null
	@grep -c "LaTeX Warning: Reference" main.log | sed 's/^/unresolved refs: /'

twocol:
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=main-twocol "\def\twocol{}\input{main.tex}" >/dev/null
	bibtex main-twocol >/dev/null
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=main-twocol "\def\twocol{}\input{main.tex}" >/dev/null
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=main-twocol "\def\twocol{}\input{main.tex}" >/dev/null
	@grep -c "LaTeX Warning: Reference" main-twocol.log | sed 's/^/unresolved refs: /'

clean:
	rm -f main.aux main.bbl main.blg main.log main.out main-twocol.*
