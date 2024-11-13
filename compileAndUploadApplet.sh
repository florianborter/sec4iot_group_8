#!/bin/bash
javac -source 1.2 -target 1.1 -g -cp ./jc211_kit/bin/api.jar:./lib/javacardx-crypto.jar ./src/ewallet/EWallet.java && \
java -classpath ./jc211_kit/bin/converter.jar:. com.sun.javacard.converter.Converter -verbose -exportpath ./jc211_kit/api_export_files:ewallet -classdir ./src -applet 0xa0:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1:0x2 ewallet.EWallet ewallet 0x0a:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1 1.0 && \
gpshell delete_applet.gpsh && \
gpshell list_applet.gpsh && \
gpshell upload_applet.gpsh && \
gpshell list_applet.gpsh
