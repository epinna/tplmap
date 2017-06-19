from burp import ITab

from javax.swing import JPanel, GroupLayout, JLabel, JComboBox, JCheckBox
from java.awt import Dimension

from core.checks import plugins

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
