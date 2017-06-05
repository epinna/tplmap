from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab

from javax.swing import JPanel, GroupLayout, JLabel, JComboBox, JCheckBox
from java.awt import Dimension

from array import array
import cgi

from core.checks import plugins

class BurpExtender( IBurpExtender ):

    def registerExtenderCallbacks( self, callbacks ):
        configTab = ConfigTab( callbacks )
        callbacks.setExtensionName( 'Tplmap' )
        callbacks.addSuiteTab( configTab )
        callbacks.registerScannerCheck( ScannerCheck( callbacks, configTab ) )

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

class ScanIssue( IScanIssue ):

    def __init__( self, callbacks, baseRequestResponse, insertionPoint, channel ):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._baseRequestResponse = baseRequestResponse
        self._insertionPoint = insertionPoint
        self._channel = channel

    def getUrl( self ):
        return self._helpers.analyzeRequest( self._baseRequestResponse ).getUrl()

    def getIssueName( self ):
        return 'Server-side template injection'

    def getIssueType( self ):
        return 0x08000000

    def getSeverity( self ):
        return 'High'

    def getConfidence( self ):
        return 'Certain'

    def getIssueBackground( self ):
        return None

    def getRemediationBackground( self ):
        return None

    def getIssueDetail( self ):
        prologue_template = """
        The <b>{parameter}</b> parameter appears to be vulnerable to server-side template injection attacks.
        The template engine appears to be <b>{template}</b>.<br><br>
        """

        render_template = """
        The payload <b>{payload}</b> was submitted in the <b>{parameter}</b> parameter.
        This payload contains an <b>{template}</b> template statement.<br><br>
        The server response contained the string <b>{rendered}</b>.
        This indicates that the payload is being interpreted by a server-side template engine.<br><br>
        """

        blind_template = """
        The time-based blind payload <b>{payload}</b> was submitted in the <b>{parameter}</b> parameter.
        The application took {delta:f} milliseconds to respond to the request, compared with {average} milliseconds for the average, indicating that the injected command caused a time delay.<br><br>
        """

        info_template = """
        Identified Informations:<br>
        <ul>
          <li>Template engine: {template}</li>
          <li>Server side language: {language}</li>
          <li>Technique: {technique}</li>
          <li>OS: {os}</li>
        </ul>
        Capabilities:
        <ul>
          <li>{execute_method}: {execute}</li>
          <li>File read: {read}</li>
          <li>File write: {write}</li>
          <li>Bind shell: {bind_shell}</li>
          <li>Reverse shell: {reverse_shell}</li>
        </ul>
        """

        data = self._channel.data
        parameter = cgi.escape( self._insertionPoint.getInsertionPointName() )
        template = data.get( 'engine' )
        language = data.get( 'language' )
        prologue = prologue_template.format( parameter=parameter, template=template, language=language )

        if self._channel.technique == 'render':
            payload = self._channel.messages[ self._channel.detect_offset - 1 ].get( 'injection' )
            technique_part = render_template.format(
                parameter = parameter,
                template = template,
                payload = cgi.escape( payload ),
                rendered = cgi.escape( self._channel.detail.get( 'expected' ) ) )
            execute_method = 'execute'
        elif self._channel.technique == 'blind':
            blind_true_payload = self._channel.messages[ self._channel.detect_offset - 2 ].get( 'injection' )
            detail = self._channel.detail
            blind_true_detail = detail.get( 'blind_true' )
            average = ( detail.get( 'average' ) / 1000.0 )
            delta_true = blind_true_detail.get( 'end' ) - blind_true_detail.get( 'start' )
            delta_true_milliseconds = ( delta_true.seconds * 1000000.0 + delta_true.microseconds ) / 1000.0
            technique_part = blind_template.format(
                payload = cgi.escape( blind_true_payload ),
                parameter = parameter,
                average = average,
                delta = delta_true_milliseconds )
            execute_method = 'execute_blind'

        _okng = lambda f: 'OK' if f else 'NG'
        info_part = info_template.format(
            template = template,
            language = language,
            technique = self._channel.technique,
            os = data.get( 'os', 'undetected' ),
            execute_method = execute_method,
            execute = _okng( data.get( execute_method ) ),
            read = _okng( data.get( 'read' ) ),
            write = _okng( data.get( 'write' ) ),
            bind_shell = _okng( data.get( 'bind_shell' ) ),
            reverse_shell = _okng( data.get( 'reverse_shell' ) ) )
        return prologue + technique_part + info_part

    def getRemediationDetail( self ):
        return None

    def getHttpMessages( self ):
        if self._channel.technique == 'render':
            responseMarkString = self._channel.detail.get( 'expected' )
            detectedMessage = self._channel.messages[ self._channel.detect_offset - 1 ]
            messages = [ self._markHttpMessage( detectedMessage.get( 'requestResponse' ), detectedMessage.get( 'injection' ), responseMarkString ) ]
        elif self._channel.technique == 'blind':
            blind_true_message = self._channel.messages[ self._channel.detect_offset - 2 ]
            blind_false_message = self._channel.messages[ self._channel.detect_offset - 1 ]
            messages = [
                self._markHttpMessage( blind_true_message.get( 'requestResponse' ), blind_true_message.get( 'injection' ), None ),
                self._markHttpMessage( blind_false_message.get( 'requestResponse' ), blind_false_message.get( 'injection' ), None ) ]
        for evaluate in self._channel.messages[ self._channel.detect_offset: ]:
            messages.append( self._markHttpMessage( evaluate.get( 'requestResponse' ), evaluate.get( 'injection' ), None ) )
        return messages

    def getHttpService( self ):
        return self._baseRequestResponse.getHttpService()

    def _markHttpMessage( self, requestResponse, injection, responseMarkString ):
        responseMarkers = None
        if responseMarkString:
            response = requestResponse.getResponse()
            responseMarkBytes = self._helpers.stringToBytes( responseMarkString )
            start = self._helpers.indexOf( response, responseMarkBytes, False, 0, len( response ) )
            if -1 < start:
                responseMarkers = [ array( 'i',[ start, start + len( responseMarkBytes ) ] ) ]

        requestHighlights = [ self._insertionPoint.getPayloadOffsets( self._helpers.stringToBytes( injection ) ) ]
        return self._callbacks.applyMarkers( requestResponse, requestHighlights, responseMarkers )

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

class ConfigTab( ITab, JPanel ):

    def __init__( self, callbacks ):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.__initLayout__()

    def __initLayout__( self ):
        self._levelComboBox = JComboBox()
        levelComboBoxSize = Dimension( 300, 30 )
        self._levelComboBox.setPreferredSize( levelComboBoxSize )
        self._levelComboBox.setMaximumSize( levelComboBoxSize )
        for level in range( 0, 6 ):
            self._levelComboBox.addItem( str( level ) )

        self._techRenderedCheckBox = JCheckBox( 'Rendered', True )
        self._techTimebasedCheckBox = JCheckBox( 'Time-based', True )

        self._plugin_groups = {}
        for plugin in plugins:
            parent = plugin.__base__.__name__
            if not self._plugin_groups.has_key( parent ):
                self._plugin_groups[ parent ] = []
            self._plugin_groups[ parent ].append( plugin )
        self._pluginCheckBoxes = []
        for pluginGroup in self._plugin_groups.values():
            for plugin in pluginGroup:
                self._pluginCheckBoxes.append( PluginCheckBox( plugin ) )

        self._positionReplaceCheckBox = JCheckBox( 'Replace', True )
        self._positionAppendCheckBox = JCheckBox( 'Append', False )

        displayItems = (
            {
                'label': 'Level',
                'components': ( self._levelComboBox, ),
                'description': 'Level of code context escape to perform (1-5, Default:0).'
            },
            {
                'label': 'Techniques',
                'components': ( self._techRenderedCheckBox, self._techTimebasedCheckBox, ),
                'description': 'Techniques R(endered) T(ime-based blind). Default: RT.'
            },
            {
                'label': 'Template Engines',
                'components': self._pluginCheckBoxes,
                'description': 'Force back-end template engine to this value(s).'
            },
            {
                'label': 'Payload position',
                'components': ( self._positionReplaceCheckBox, self._positionAppendCheckBox, ),
                'description': 'Scan payload position. This feature only appears in BurpExtension.'
            }
        )

        layout = GroupLayout( self )
        self.setLayout( layout )
        layout.setAutoCreateGaps( True )
        layout.setAutoCreateContainerGaps( True )

        labelWidth = 200
        hgroup =  layout.createParallelGroup( GroupLayout.Alignment.LEADING )
        vgroup = layout.createSequentialGroup()
        for displayItem in displayItems:
            label = JLabel( displayItem.get( 'label' ) )
            label.setToolTipText( displayItem.get( 'description' ) )
            _hgroup = layout.createSequentialGroup().addComponent( label, labelWidth, labelWidth, labelWidth )
            _vgroup = layout.createParallelGroup( GroupLayout.Alignment.BASELINE ).addComponent( label )
            for component in displayItem.get( 'components' ):
                _hgroup.addComponent( component )
                _vgroup.addComponent( component )
            hgroup.addGroup( _hgroup )
            vgroup.addGroup( _vgroup )

        layout.setHorizontalGroup( hgroup )
        layout.setVerticalGroup( vgroup )

    def getTabCaption( self ):
        return 'Tplmap'

    def getUiComponent( self ):
        return self

    def getLevel( self ):
        return self._levelComboBox.getSelectedIndex()

    def getTechniques( self ):
        return '%s%s' % ( 'R' if self._techRenderedCheckBox.isSelected() else '', 'T' if self._techTimebasedCheckBox.isSelected() else '' )

    def getEngines( self ):
        return [ checkbox.getPlugin() for checkbox in self._pluginCheckBoxes if checkbox.isSelected() ]

    def getPayloadPosition( self ):
        return { 'replace': self._positionReplaceCheckBox.isSelected(), 'append': self._positionAppendCheckBox.isSelected() }

class PluginCheckBox( JCheckBox ):

    def __init__( self, plugin ):
        JCheckBox.__init__( self, plugin.__name__, True )
        self._plugin = plugin
        parent = plugin.__base__.__name__
        tooltip = parent if( parent != 'Plugin' ) else 'eval'
        self.setToolTipText( tooltip )

    def getPlugin( self ):
        return self._plugin
