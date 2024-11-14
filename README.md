# sec4iot_group_8
The repository for our group project (group 8) in the module "Security for IoT". 


# Applet
## Compile the applet on
Compile the java in the project root as follows:
`javac -source 1.2 -target 1.1 -g -cp ./jc211_kit/bin/api.jar:./lib/javacardx-crypto.jar ./src/floalaalex/util/CryptoUtil.java ./src/floalaalex/ewallet/EWallet.java`

execute this command in the project root to convert into a cap file.

`java -classpath ./jc211_kit/bin/converter.jar com.sun.javacard.converter.Converter \
  -verbose \
  -exportpath ./jc211_kit/api_export_files \
  -classdir ./src \
  -applet 0xa0:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1:0x2 floalaalex.ewallet.EWallet floalaalex.ewallet 0x0a:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1 1.0`

## Delete / list / upload the applet onto the card
list the applets via `gpshell list_applet.gpsh`
delete the applets via `gpshell delete_applet.gpsh`
upload a new applet via `gpshell upload_applet.gpsh` (Check in this file that the path to the .cap is correct!)

Also in this scripts, make sure, that the App ID is always the same. Apps must be deleted before they can be re-uploaded.

## Run all in one script
In the script `compileAndUploadApplet.sh` are all the above commands summed up into a single file to compile and upload the applet to the card.

# Compile the Terminal App
In project root run `javac -cp src src/floalaalex/util/CryptoUtil.java src/floalaalex/terminal/TerminalApp.java`
In project roo) run `java -cp src floalaalex.terminal.TerminalApp`

alternatively execute the "all in one" bash script `compileAndRunTerminal.sh`