from burp import IBurpExtender
from config_tab import ConfigTab
from scanner_check import ScannerCheck

class BurpExtender( IBurpExtender ):

    def registerExtenderCallbacks( self, callbacks ):
        configTab = ConfigTab( callbacks )
        callbacks.setExtensionName( 'Tplmap' )
        callbacks.addSuiteTab( configTab )
        callbacks.registerScannerCheck( ScannerCheck( callbacks, configTab ) )

