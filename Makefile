TARGET = /usr/local/bin
SOURCE = $(shell pwd)
FILES = $(shell ls | sed "/LICENSE/d;/README/d;/Makefile/d;/~$$/d")

all: install
	@echo "Finished."

.PHONY: make
install:
	@echo "Installing the utilities to $(TARGET)"
	@for FILE in $(FILES); \
			do \
				echo -e "\tInstalling $$FILE to $(TARGET)"; \
				sudo rm $(TARGET)/$$FILE; \
				sudo ln -s $(SOURCE)/$$FILE $(TARGET); \
			done
