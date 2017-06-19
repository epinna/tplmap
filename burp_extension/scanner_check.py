from burp import IScannerCheck

from channel import Channel
from scan_issue import ScanIssue

class ScannerCheck( IScannerCheck ):

    def __init__( self, callbacks, configTab ):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._configTab = configTab

    def doPassiveScan( self, baseRequestResponse ):
        return None

    def doActiveScan( self, baseRequestResponse, insertionPoint ):
        for position in [ position for ( position, selected ) in self._configTab.getPayloadPosition().items() if selected ]:
            channel = Channel( self._callbacks, self._configTab, baseRequestResponse, insertionPoint, position )
            for engineClass in self._configTab.getEngines():
                engine = engineClass( channel )
                engine.detect()
                if channel.detect:
                    return [ ScanIssue( self._callbacks, baseRequestResponse, insertionPoint, channel ) ]
        return None

    def consolidateDuplicateIssues( self, existingIssue, newIssue ):
        return 0

