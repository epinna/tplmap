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
$ wget 'https://repo1.maven.org/maven2/org/python/jython-installer/2.7.2/jython-installer-2.7.2.jar' -O jython_installer.jar
$ mkdir "$HOME"/jython
$ java -jar jython_installer.jar -s -d "$HOME"/jython -t standard
$ rm jython_installer.jar
```
2. Install additional Python modules
```sh
$ curl -sL 'https://github.com/yaml/pyyaml/archive/refs/tags/5.1.2.tar.gz' | tar xzf -
$ cd pyyaml-5.1.2
$ "$HOME"/jython/bin/jython setup.py install
$ cd ..
$ curl -sL 'https://github.com/psf/requests/archive/refs/tags/v2.22.0.tar.gz' | tar xzf -
$ cd requests-2.22.0
$ "$HOME"/jython/bin/jython setup.py install
$ cd ..
$ rm -rf pyyaml-5.1.2 requests-2.22.0
```
3. Run your Burp Suite
4. Open Jython file chooser dialog
[Extender] - [Options] - [Python Environment] - [Location of the Jython standalone JAR file]
5. Choose the file `$HOME/jython/jython.jar`
6. Load `burp_extender.py` as Python type burp extension

### Scanning

Configure scanning option from 'Tplmap' tab, and do an active scan.

### Limitation

Only the detection feature of Tplmap is available.
Exploitation feature is not implemented, use Tplmap CLI.

The `--injection-tag` option is also not available, because this extension follows Burp's Insertion Point setting.

If you need the `--injection-tag` option, you can use [Scan manual insertion point](https://github.com/ClementNotin/burp-scan-manual-insertion-point) extension.
