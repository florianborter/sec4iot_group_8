# sec4iot_group_8
The repository for our group project (group 8) in the module "Security for IoT". 


# Applet
## Compile the applet on
Compile the java in the directory "~/workspace/smartcard_hello_world"
as follows:
`javac -source 1.2 -target 1.1 -g -cp /home/flobo/workspace/oracle_javacard_sdks/jc211_kit/bin/api.jar ./src/floalaalex.ewallet/EWallet.java`

execute this command in the directory "~/workspace/smartcard_hello_world"
to convert into a cap file.

`java -classpath /home/flobo/workspace/oracle_javacard_sdks/jc211_kit/bin/converter.jar:. com.sun.javacard.converter.Converter -verbose -exportpath /home/flobo/workspace/oracle_javacard_sdks/jc211_kit/api_export_files:floalaalex.ewallet -classdir ./src -applet 0xa0:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1:0x2 floalaalex.ewallet.EWallet floalaalex.ewallet 0x0a:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x6:0x1 1.0`

Note: In case you are on another machine, make sure to change the path to ther converter.jar as well as the value of -exportpath to point to your jc211_kit.

## Delete / list / upload the applet onto the card
list the applets via `gpshell list_applet.gpsh`
delete the applets via `gpshell delete_applet.gpsh`
upload a new applet via `gpshell upload_applet.gpsh` (Check in this file that the path to the .cap is correct!)

Also in this scripts, make sure, that the App ID is always the same. Apps must be deleted before they can be reuploaded.

## Run all in one script
In the script `compileAndUploadApplet.sh` are all the above commands summed up into a single file to compile and upload the applet to the card. Before usage: make sure all the path are adjusted to your local installation.

# Compile the floalaalex.terminal App
In directory "~/workspace/smartcard_hello_world" (project root) run `javac src/floalaalex.terminal/TerminalApp.java`
In directory "~workspace/smartcard_hello_world" (project root) run `java -cp src floalaalex.terminal.TerminalApp`

alternatively execute the bash script `compileAndRunTerminal.sh`