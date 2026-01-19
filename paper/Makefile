.PHONY: all clean

PAPER = aflock

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex
	pdflatex -interaction=nonstopmode $(PAPER).tex
	pdflatex -interaction=nonstopmode $(PAPER).tex
	pdflatex -interaction=nonstopmode $(PAPER).tex

clean:
	rm -f $(PAPER).pdf $(PAPER).aux $(PAPER).log $(PAPER).out $(PAPER).toc $(PAPER).bbl $(PAPER).blg

arxiv: $(PAPER).pdf
	@echo "For arXiv submission:"
	@echo "1. Upload $(PAPER).tex"
	@echo "2. arXiv will compile automatically"
	@echo "3. Or upload $(PAPER).pdf directly (if allowed)"
