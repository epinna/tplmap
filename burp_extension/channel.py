class Channel:

    def __init__( self, callbacks, configTab, baseRequestResponse, insertionPoint, payloadPosition ):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._configTab = configTab
        self._baseRequestResponse = baseRequestResponse
        self._insertionPoint = insertionPoint
        self._payloadPosition = payloadPosition
        self._request = self._helpers.analyzeRequest( baseRequestResponse )

        self.url = self._request.getUrl()
        self.args = {
            'level': self._configTab.getLevel(),
            'technique': self._configTab.getTechniques() }
        self.data = {}
        self.detect = False
        self.messages = []

    def req( self, injection ):
        payload = injection if self._payloadPosition == 'replace' else self._insertionPoint.getBaseValue() + injection
        checkRequest = self._insertionPoint.buildRequest( self._helpers.stringToBytes( payload ) )
        checkRequestResponse = self._callbacks.makeHttpRequest( self._baseRequestResponse.getHttpService(), checkRequest )
        self.messages.append( {
            'injection': injection,
            'requestResponse': checkRequestResponse
        } )
        return self._helpers.bytesToString( checkRequestResponse.getResponse() )

    def detected( self, technique, detail ):
        self.detect = True
        self.technique = technique
        self.detail = detail
        self.detect_offset = len( self.messages )

