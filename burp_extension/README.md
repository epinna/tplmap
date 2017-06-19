# Burp Suite Plugin

Tplmap is able to run as a Burp Suite Extension.

### Install

Load burp_extension.py with following conditions.

* Burp Suite edition: Professional
* The Python modules required for Tplmap are installed.
  * PyYaml
  * requests
* Extension type: Python

An example of a simple setup procedure:

1. Install Jython by installer
```sh
$ wget 'http://search.maven.org/remotecontent?filepath=org/python/jython-installer/2.7.0/jython-installer-2.7.0.jar' -O jython_installer.jar
$ java -jar jython_installer.jar -s -d /path/to/install/jython -t standard
```
2. Install additional Python modules
```sh
$ cd /path/to/install/jython
$ ./bin/pip install PyYaml requests
```
3. Run your Burp Suite
4. Open Jython file chooser dialog
[Extender] - [Options] - [Python Environment] - [Location of the Jython standalone JAR file]
5. Choose the file `/path/to/install/jython/jython.jar`
6. Load `burp_extender.py` as Python type burp extension

### Scanning

Configure scanning option from 'Tplmap' tab, and do an active scan.

### Limitation

Only the detection feature of Tplmap is available.
Exploitation feature is not implemented, use Tplmap CLI.

The `--injection-tag` option is also not available, because this extension follows Burp's Insertion Point setting.

If you need the `--injection-tag` option, you can use [Scan manual insertion point](https://github.com/ClementNotin/burp-scan-manual-insertion-point) extension.
