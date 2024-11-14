#!/bin/bash
# Compile the TerminalApp and CryptoUtil
javac -cp src src/floalaalex/util/CryptoUtil.java src/floalaalex/terminal/TerminalApp.java && \
# Run the TerminalApp
java -cp src floalaalex.terminal.TerminalApp
