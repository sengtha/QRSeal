# Build the preprint.  Requires texlive-latex-base, -recommended, -extra and
# latexmk.  `make` produces main.pdf.

.PHONY: all clean watch

all: main.pdf

main.pdf: main.tex references.bib
	latexmk -pdf -interaction=nonstopmode main.tex

watch:
	latexmk -pdf -pvc main.tex

clean:
	latexmk -C
