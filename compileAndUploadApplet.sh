#!/bin/bash
# Compile the EWallet applet and CryptoUtil
javac -source 1.2 -target 1.1 -g -cp ./jc211_kit/bin/api.jar:./lib/javacardx-crypto.jar ./src/floalaalex/util/CryptoUtil.java ./src/floalaalex/ewallet/EWallet.java && \
# Convert the applet classes to a CAP file
java -classpath ./jc211_kit/bin/converter.jar com.sun.javacard.converter.Converter \
  -verbose \
  -exportpath ./jc211_kit/api_export_files \
  -classdir ./src \
  -applet 0xa0:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1:0x2 floalaalex.ewallet.EWallet floalaalex.ewallet 0x0a:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1 1.0 && \
# Use gpshell to delete, list, upload, and list the applet again
gpshell delete_applet.gpsh && \
gpshell list_applet.gpsh && \
gpshell upload_applet.gpsh && \
gpshell list_applet.gpsh
