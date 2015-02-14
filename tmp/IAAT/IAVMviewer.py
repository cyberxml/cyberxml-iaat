import wx
import wx.aui
import wx.stc as stc
import io, sys, wx, re,os, wx.html
from lxml import etree


inputfile='./empty.xml' #Defualt loaded file
xml_file=open(inputfile,'r')
lnum=0
pretty=False
scrolltxt=True
validtag=['StGermainData', 'element', 'import', 'toolbox', 'plugins', 'components', 'list', 'include', 'struct', 'param','Empty', 'sourceFile','searchPath','replace','merge','append']
stn_validtag=['StGermainData','list','struct','param','include','asciidata','columnDefinition','sourceFile','searchPath','replace','merge','append']
iavm_validtag=['IAVMtoCVE', 'IAVM', 'S', 'Revision', 'CVEs', 'CVENumber', 'Vendor','CPEs','CPE','References', 'Reference',]
swcat_validtag=['ai:assets','assets','ai','Asset','ai:CanonicalID','CanonicalID','Software','ai:CPE','CPE',]
variablestag='VARIABLES'
var_colours=['blue','green','red','yellow','cyan','orange']

global namespace, newroot

def main(argv):
    global inputfile
    inputfile=argv



if wx.Platform == '__WXMSW__':
      faces = { 'times': 'Times New Roman',
                    'mono' : 'Courier New',
                    'helv' : 'Verdana',
                    'other': 'Comic Sans MS',
                    'size' : 10,
                    'size2': 9,
                   }
else:
      faces = { 'times': 'Times',
                    'mono' : 'Courier',
                    'helv' : 'Helvetica',
                    'other': 'new century schoolbook',
                    'size' : 10,
                    'size2': 9,
                   }

def strip_namespace(eltree, namespace=None,remove_from_attr=True):
    #remove specific namespace from parsed XML.
    ns = '{%s}' % namespace
    nslen = len(ns)
    for elem in eltree.getiterator():
        
        try: 
            elem.tag.startswith(ns)
            elem.tag = elem.tag[nslen:]
        except:
            continue 
        if remove_from_attr:
            to_delete=[]
            to_set={}
        for attr_name in elem.attrib:
            if attr_name.startswith(ns):
                old_val = elem.attrib[attr_name]
                to_delete.append(attr_name)
                attr_name = attr_name[nslen:]
                to_set[attr_name] = old_val
        for key in to_delete:
            elem.attrib.pop(key)
        elem.attrib.update(to_set)
           
            

                
class MyFrame(wx.Frame):
    global newroot
    def __init__(self, *args, **kwargs):
        wx.Frame.__init__(self, *args, **kwargs)

        self.mgr = wx.aui.AuiManager(self)

        leftpanel = wx.Panel(self, -1)
        rightpanel = wx.Panel(self, -1)
        #bottompanel = wx.Panel(self, -1)
        
        self.stc = wx.stc.StyledTextCtrl(self, size=(500,700))
        self.vistree = wx.TreeCtrl(self, -1, size=(400, 700), style=wx.TR_HAS_BUTTONS|wx.TR_LINES_AT_ROOT|wx.TR_FULL_ROW_HIGHLIGHT|wx.TR_DEFAULT_STYLE|wx.SUNKEN_BORDER)
        self.stc.SetMarginType(1, stc.STC_MARGIN_NUMBER)
        self.stc.SetMarginWidth(1,30)
        
        #self.mgr.AddPane(bottompanel, wx.aui.AuiPaneInfo().Bottom(), 'Information Pane')
        self.mgr.AddPane(self.vistree, wx.aui.AuiPaneInfo().Left().Layer(0),'Tree Navigator')
        self.mgr.AddPane(self.stc, wx.aui.AuiPaneInfo().Center().Layer(1), 'Editor Pane')        
        
        self.mgr.Update()
    
        self.main_frame_menubar = wx.MenuBar()
        self.file = wx.Menu()
        self.open_file = wx.MenuItem(self.file, wx.NewId(), "Open File", "", wx.ITEM_NORMAL)
        self.file.AppendItem(self.open_file)
#        self.close_file = wx.MenuItem(self.file, wx.NewId(), "Close File", "", wx.ITEM_NORMAL)
#        self.file.AppendItem(self.close_file)
        self.file.AppendSeparator()
        self.exit = wx.MenuItem(self.file, wx.NewId(), "Exit", "", wx.ITEM_NORMAL)
        self.file.AppendItem(self.exit)
        self.main_frame_menubar.Append(self.file, "File")
        self.pview = wx.Menu()
        self.selpretty = wx.MenuItem(self.pview, wx.NewId(), "Toggle", "", wx.ITEM_NORMAL)
##        self.pview.AppendItem(self.selpretty)
##        self.main_frame_menubar.Append(self.pview, "Pretty XML") 
        self.codex_view = wx.Menu()
        self.open_codex = wx.MenuItem(self.codex_view, wx.NewId(), "Launch Browser", "", wx.ITEM_NORMAL)
        self.codex_view.AppendItem(self.open_codex)
        self.main_frame_menubar.Append(self.codex_view, "CODEX View")
        self.selsort = wx.Menu()       
        self.tsort = wx.MenuItem(self.selsort, wx.NewId(), "Sort A-Z,a-z", "", wx.ITEM_NORMAL)
        self.selsort.AppendItem(self.tsort)
        self.main_frame_menubar.Append(self.selsort, "Sort Tree")         
    
        self.SetMenuBar(self.main_frame_menubar)
        # Event handlers
        self.Bind(wx.EVT_MENU, self.openfilemenu, self.open_file)
#        self.Bind(wx.EVT_MENU, self.closefilemenu, self.close_file)
        self.Bind(wx.EVT_MENU, self.exitprog, self.exit)
        self.Bind(wx.EVT_MENU, self.prettyv, self.selpretty)        
        self.Bind(wx.EVT_MENU, self.openhtmlcodex, self.open_codex)        
        self.Bind(wx.EVT_MENU, self.OnSortChildren, self.tsort)
        self.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnSelChanged, self.vistree)
        self.Bind(wx.EVT_TREE_ITEM_EXPANDING, self.OnExpanding, self.vistree)
        self.Bind(wx.EVT_TREE_ITEM_ACTIVATED, self.OnItemSelected, self.vistree)
        self.Bind(wx.EVT_TREE_ITEM_COLLAPSING, self.OnCollapsing, self.vistree)
        self.Bind(wx.EVT_TREE_ITEM_COLLAPSED, self.OnCollapsed, self.vistree)
        self.Bind(wx.EVT_TREE_ITEM_EXPANDED, self.OnExpanded, self.vistree)
        # Toolbar events
        self.Bind(wx.EVT_TOOL, self.openfilemenu, id=1)
        self.Bind(wx.EVT_TOOL, self.OnSortChildren, id=2)
        self.Bind(wx.EVT_TOOL, self.prettyv, id=3)
        self.Bind(wx.EVT_TOOL, self.openhtmlcodex, id=4)
        self.Bind(wx.EVT_TOOL, self.exitprog, id=5)
        self.Bind(wx.EVT_TOOL, self.onexp,  id=10)
        self.Bind(wx.EVT_TOGGLEBUTTON, self.onToggleexp, id=6) 
        self.Bind(wx.EVT_TOOL, self.prevsearch, id=7)
        self.Bind(wx.EVT_TOOL, self.nextsearch, id=8)
        self.Bind(wx.EVT_TEXT_ENTER, self.OnTextEnter, id = 9) # from TestCtrl 
        self.Bind(wx.EVT_SEARCHCTRL_CANCEL_BTN,  self.OnTextCancel,  id=9)        
        
        
                # Tool Bar - Most functions moved to toolbar
        self.myframe_toolbar = wx.ToolBar(self, -1)
        self.SetToolBar(self.myframe_toolbar)
        self.myframe_toolbar.AddSeparator()
        self.myframe_toolbar.AddLabelTool(1, "Open File",
             wx.Bitmap(os.path.expanduser('./document_text_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Open XML File", "Open XML Flatfile")
        self.myframe_toolbar.AddSeparator()
        self.myframe_toolbar.AddLabelTool(2, "Sort A-Z",
             wx.Bitmap(os.path.expanduser('./arrow_full_down_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Sort A-Z", "Sort Descending A-Z, a-z")
##        self.myframe_toolbar.AddLabelTool(3, "Pretty XML",
##             wx.Bitmap(os.path.expanduser('./icons/text-xml.png'), wx.BITMAP_TYPE_ANY),
##             wx.NullBitmap, wx.ITEM_NORMAL, "Toggle View Mode", "View XML in pretty mode")
        self.myframe_toolbar.AddLabelTool(4, "Open CODEX",
             wx.Bitmap(os.path.expanduser('./website_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Open CODEX Browser", "Browse Underworld CODEX")
        self.myframe_toolbar.AddSeparator()
        self.myframe_toolbar.AddLabelTool(5, "Exit",
             wx.Bitmap(os.path.expanduser('./logout_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Exit", "Exit Flatfile Viewer")
        self.myframe_toolbar.AddSeparator()

# ------------ Will use for Search All and Search & Replace funcions at later stage ---------
#        self.myframe_toolbar.AddLabelTool(6, "Search",
#             wx.Bitmap("/home/marke/Downloads/Magnifier.png", wx.BITMAP_TYPE_ANY),
#             wx.NullBitmap, wx.ITEM_NORMAL, "Search", "Search")
# ---------------------------------------------------------------------------------
        self.myframe_toolbar.AddLabelTool(10, "Expand Branch",
        wx.Bitmap(os.path.expanduser('./ontology_16.png'), wx.BITMAP_TYPE_ANY), 
        wx.NullBitmap, wx.ITEM_NORMAL, "Expand Branch", "Expand Branch Structure")

        # create a toggle button
        self.expandbutton = wx.ToggleButton(self.myframe_toolbar,6,  size=(85, 35),  label="Expand All") 
        self.myframe_toolbar.AddControl(self.expandbutton)

        self.myframe_toolbar.AddLabelTool(7, "Previous",
             wx.Bitmap(os.path.expanduser('./arrow_sans_left_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Previous", "Previous Match")  
        self.myframe_toolbar.AddLabelTool(8, "Next",
             wx.Bitmap(os.path.expanduser('./arrow_sans_right_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Next", "Next Match")               
        self.searchdiag= wx.SearchCtrl(self.myframe_toolbar, 9, "", wx.DefaultPosition , wx.Size(250, 30),style=wx.TE_PROCESS_ENTER )   
        self.myframe_toolbar.AddControl(self.searchdiag)
        #self.searchdiag.SetDescriptiveText("Press Enter")

        self.wholewrd = wx.RadioButton(self.myframe_toolbar, -1, ("Whole Word "))
        self.myframe_toolbar.AddControl(self.wholewrd)  
        self.matchcase = wx.RadioButton(self.myframe_toolbar, -1, ("Match Case "))
        self.myframe_toolbar.AddControl(self.matchcase)
        self.wrdstart = wx.RadioButton(self.myframe_toolbar, -1, ("Word Start "))
        self.myframe_toolbar.AddControl(self.wrdstart)
        # Tool Bar end  
        
        self.__set_properties()
        
    def __set_properties(self):
        self.dirname=''
        self.myframe_toolbar_statusbar=self.CreateStatusBar(1, 0)
        self.myframe_toolbar.Realize()
        self.myframe_toolbar_statusbar.SetStatusWidths([-1])
        self.SetStatusText(inputfile)
        self.searchdiag.ShowCancelButton(True)    
        self.searchdiag.SetDescriptiveText('Enter search..')
        self.SetTitle("CyberXML IAVM Applicability Analysis Tool")
        #self.SetMinSize((1200, 750))
        self.vistree.SetBackgroundColour(wx.Colour(216, 216, 191))
        self.stc.SetCodePage(wx.stc.STC_CP_UTF8 )## *********** Remove for MSWin machines!****************##
        xmlkeywords = ("type param element name list struct import components plugins")

        self.stc.SetLexer(stc.STC_LEX_XML)
        #self.stc.SetLexerLanguage('xml') # Need to set styling bits to 7 next        
        self.stc.SetStyleBits(7)
        self.stc.SetKeyWords(5, "".join(xmlkeywords))
        self.stc.StyleSetSpec(stc.STC_STYLE_DEFAULT,"face:%(helv)s,size:%(size)d" %faces)
        #self.stc.StyleSetSpec(5,"fore:#0000FF,bold,underline,size:%(size)d" % faces)        

        # more global default styles for all languages
        self.stc.StyleSetSpec(stc.STC_STYLE_LINENUMBER,
            "back:#C0C0C0,face:%(helv)s,size:%(size2)d" % faces)
        self.stc.StyleSetSpec(stc.STC_STYLE_CONTROLCHAR,
            "face:%(other)s" % faces)
        self.stc.StyleSetSpec(stc.STC_STYLE_BRACELIGHT,
            "fore:#FFFFFF,back:#0000FF,bold")
        self.stc.StyleSetSpec(stc.STC_STYLE_BRACEBAD,
            "fore:#000000,back:#FF0000,bold")

# -----------  used Python default. XML Lexer NOT working! ---------
        self.stc.StyleSetSpec(stc.STC_P_DEFAULT,
            "fore:#000000,face:%(helv)s,size:%(size)d" % faces)
        # comments
        self.stc.StyleSetSpec(stc.STC_P_COMMENTLINE,
            "fore:#007F00,face:%(other)s,size:%(size)d" % faces)
        # number
        self.stc.StyleSetSpec(stc.STC_P_NUMBER,
            "fore:#007F7F,size:%(size)d" % faces)
        # string
        self.stc.StyleSetSpec(stc.STC_P_STRING,
            "fore:#7F007F,face:%(helv)s,size:%(size)d" % faces)
        # single quoted string
        self.stc.StyleSetSpec(stc.STC_P_CHARACTER,
            "fore:#7F007F,face:%(helv)s,size:%(size)d" % faces)
        # keyword
        self.stc.StyleSetSpec(stc.STC_P_WORD,
            "fore:#00007F,bold,size:%(size)d" % faces)
        # triple quotes
        self.stc.StyleSetSpec(stc.STC_P_TRIPLE,
            "fore:#7F0000,size:%(size)d" % faces)
        # triple double quotes
        self.stc.StyleSetSpec(stc.STC_P_TRIPLEDOUBLE,
            "fore:#7F0000,size:%(size)d" % faces)

        # function or method name definition
        self.stc.StyleSetSpec(stc.STC_P_DEFNAME,
            "fore:#007F7F,bold,size:%(size)d" % faces)
        # operators
        self.stc.StyleSetSpec(stc.STC_P_OPERATOR,
            "bold,size:%(size)d" % faces)
        # identifiers
        self.stc.StyleSetSpec(stc.STC_P_IDENTIFIER,
            "fore:#000000,face:%(helv)s,size:%(size)d" % faces)
        # comment-blocks
        self.stc.StyleSetSpec(stc.STC_P_COMMENTBLOCK,
            "fore:#7F7F7F,size:%(size)d" % faces)
        # end of line where string is not closed
        self.stc.StyleSetSpec(stc.STC_P_STRINGEOL,
            "fore:#000000,face:%(mono)s,back:#E0C0E0,eol,size:%(size)d"\
                % faces)
# ---------- END  Python Style Lexer ------
        xml_file = inputfile
        self.stc.SetText(open(xml_file).read())
        self.stc.EnsureCaretVisible()
        self.stc.SetCaretLineVisible(1)
        self.stc.SetCaretLineBack("yellow")
        self.stc.SetCaretForeground("black")
        self.stc.SetCaretWidth(2)  
              
    def openfilemenu(self, event): # wxGlade: MyFrame.<event_handler>
        """ Open a file"""
        global new_namespace
        dlg = wx.FileDialog(self, "Choose an XML file", self.dirname, "", "*.xml", wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.filename = dlg.GetFilename()
            self.dirname = dlg.GetDirectory()
            xml_file=open(os.path.join(self.dirname, self.filename), 'r')
            print xml_file
            newtree = etree.parse(xml_file)
            new_namespace = newtree.getroot().tag[1:].split("}")[0]
            strip_namespace(newtree,new_namespace,True)   
            newroot=newtree.getroot()
            self.vistree.DeleteAllItems()      
            frame.loadtree(newtree)
            self.expandbutton.SetValue(False) 
            self.SetStatusText(os.path.join(self.dirname, self.filename))
        dlg.Destroy()

        selectionID=self.vistree.GetRootItem()        
        XMLdata=self.vistree.GetPyData(selectionID)
        try:
            self.stc.SetText(etree.tostring(newroot, pretty_print=True))   
            if scrolltxt:
                self.stc.ScrollToLine(0) # scroll display on StyledTextCtrl window
                self.vistree.Expand(selectionID) 
            else:
                pass 
                   
        except:
            pass    


    def closefilemenu(self, event): # wxGlade: MyFrame.<event_handler>
        event.Skip()

    def exitprog(self, event): # wxGlade: MyFrame.<event_handler>
        self.Close()

    def OnSelChanged(self, event): # wxGlade: MyFrame.<event_handler>
        selectionID=self.vistree.GetSelection()
        XMLdata=self.vistree.GetPyData(selectionID)['id_num'] # show the parameter variable values stored by SetPyData
        linenumber=self.vistree.GetPyData(selectionID)['line_num']
        self.stc.ScrollToLine(linenumber-12) # scroll on StyledTextCtrl window
        self.stc.GotoLine(linenumber-1)
        start=self.stc.GetCurrentPos()
        end=self.stc.GetLineEndPosition(linenumber-1)
        self.stc.SetSelection(start,end)



    def OnTextEnter(self, event):
        self.stc.SetSelection(0, 1)
        doclength= self.stc.GetLength()
        searchstring=self.searchdiag.GetValue() # ******* Trap 0 length search characters !!!!!!!!
        if searchstring!="":
            if self.wholewrd.GetValue()==True:
                find_flag=wx.stc.STC_FIND_WHOLEWORD
            elif self.matchcase.GetValue()==True:
                find_flag=wx.stc.STC_FIND_MATCHCASE
            else:
                find_flag=wx.stc.STC_FIND_WORDSTART
            found= self.stc.FindText(0, doclength, searchstring , find_flag )
            self.stc.SetSelection(found, self.stc.WordEndPosition(found, 1))
            self.stc.SetCurrentPos(self.stc.GetSelectionEnd())
            self.stc.ScrollToLine(self.stc.LineFromPosition(found)-12)
        else:
            pass
    
    def OnTextCancel(self,  event):
        self.searchdiag.Clear()
        
    def OnSearchNode(self, event): # Search nodes in tree
        event.Skip()

        
    def nextsearch(self, event): # Text typed into search field  
        searchstring=self.searchdiag.GetValue() # ******* Trap 0 length search characters !!!!!!!!
        if searchstring!="":            
            if self.wholewrd.GetValue()==True:
                find_flag=wx.stc.STC_FIND_WHOLEWORD
            elif self.matchcase.GetValue()==True:
                find_flag=wx.stc.STC_FIND_MATCHCASE
            else:
                find_flag=wx.stc.STC_FIND_WORDSTART    
            self.stc.SetCurrentPos(self.stc.GetSelectionEnd())
            self.stc.SetSelection(self.stc.GetCurrentPos(), self.stc.GetCurrentPos())    
            self.stc.SearchAnchor()        
            nextfound= self.stc.SearchNext(find_flag, searchstring )
            self.stc.ScrollToLine(self.stc.LineFromPosition(nextfound)-12)
        else:
            pass
    
    def prevsearch(self, event):
        searchstring=self.searchdiag.GetValue()
        if searchstring!="":        
            if self.wholewrd.GetValue()==True:
                find_flag=wx.stc.STC_FIND_WHOLEWORD
            elif self.matchcase.GetValue()==True:
                find_flag=wx.stc.STC_FIND_MATCHCASE
            else:
                find_flag=wx.stc.STC_FIND_WORDSTART            

            self.stc.SearchAnchor()        
            prevfound= self.stc.SearchPrev(find_flag, searchstring )
            self.stc.ScrollToLine(self.stc.LineFromPosition(prevfound)-12)
        else:
            pass
        
    def prettyv(self, event): # wxGlade: MyFrame.<event_handler>
            global pretty
            pretty= not pretty
        
    
    def chkflags(self):
        if self.wholewrd.GetValue():
            find_flag=wx.stc.STC_FIND_WHOLEWORD
        elif self.matchcase.GetValue():
            find_flag=wx.stc.STC_FIND_MATCHCASE
        else:
            find_flag=wx.stc.STC_FIND_WORDSTART      
        return find_flag

    def openhtmlcodex(self, event): # wxGlade: MyFrame.<event_handler>
        frm = MyHtmlFrame(None, "Underworld CODEX Browser")
        frm.Show()
        

    def OnExpanding(self, event): # wxGlade: MyFrame.<event_handler>
        event.Skip()

    def OnItemSelected(self, event): # wxGlade: MyFrame.<event_handler>
         event.Skip()

    def OnCollapsing(self, event): # wxGlade: MyFrame.<event_handler>
        event.Skip()

    def OnCollapsed(self, event): # wxGlade: MyFrame.<event_handler>
        event.Skip()

    def OnExpanded(self, event): # wxGlade: MyFrame.<event_handler>
        event.Skip()

    def OnSortChildren(self, event):
        node=self.vistree.GetSelection()
        if node:
            self.vistree.SortChildren(node)
            
    def onToggleexp(self,  event):
        if self.expandbutton.GetValue():
            self.vistree.ExpandAll()
        else:
            self.vistree.CollapseAll()
            node=self.vistree.GetSelection()
            self.vistree.Expand(node)
    def onexp(self,  event):    
            node=self.vistree.GetSelection()
            self.vistree.Expand(node)        


    def loadtree(self,roottree):
        #Populate tree structure with XML children
        rootn=roottree.getroot()
        lnum=roottree.getroot().sourceline
        newroot=rootn
        
        def VarList(self, rnode): # gather all "floating" variables in input file
            treevar=self.vistree.AppendItem(rnode, variablestag)# Create VAR tree node list from address of first var found
            self.vistree.SetPyData(treevar, {"id_num":'Collected Variables',"line_num":lnum})
            firstchild, cookie=self.vistree.GetFirstChild(rnode)
            numchilds=self.vistree.GetChildrenCount(rnode, False) #Should not count children recursively
            sibling=firstchild

            def MoveVars(self, child, parent): # parent now "Variables" dir on tree
                newchild=self.vistree.AppendItem(parent ,self.vistree.GetItemText(child))
                if self.vistree.GetItemTextColour(child) in var_colours: #'blue': # Need to preserve colour during move
                    self.vistree.SetItemTextColour(newchild, self.vistree.GetItemTextColour(child))
                
                copydata=self.vistree.GetPyData(child)["id_num"]
                copyline=self.vistree.GetPyData(child)["line_num"]
                self.vistree.SetPyData(newchild, {"id_num":copydata,"line_num":copyline})


            for treechild in range(1, numchilds): # main loop for cleanup.

                if (self.vistree.ItemHasChildren(sibling))==False:
                    MoveVars(self, sibling, treevar) # move all to new VAR tree dir
                    oldsibling=sibling
                    sibling=self.vistree.GetNextSibling(sibling)
                    self.vistree.Delete(oldsibling)
                else:
                    sibling=self.vistree.GetNextSibling(sibling)
                    
        # end --------- VarList --------                    
        
        
        def initialize(self,filetype,line_num):
            global treedic, parentnode_txt,rootnode
            rootnode=self.vistree.AddRoot(filetype) # string parameter & returns an ID
            self.vistree.SetPyData(rootnode,{"id_num":rootnode,"line_num":lnum} ) 
            treedic={filetype:rootnode}
            parentnode_txt=filetype
            
        
        #if rootn.findtext('struct')!=None: # XML flatfile or standard flatfile test
            print ("line 485")
        if "assets" in rootn.tag: # SWCat
            print ("line 486")
            initialize(self,'Standard XML Input',lnum)
            offset=lnum-1 # offset beggining of file
            for node in roottree.iter():        
                
                if node.tag in swcat_validtag:
                                    
                    # STANDARD FILE PROCESS
                    
                    try:
                        parentnodeID=treedic[node.getparent()]
                           
                    except KeyError:# for StGerMainData root  Parent type = None 
                        parentnodeID=treedic[parentnode_txt]

                    lnum=node.sourceline-offset
                    try: 
                        name_attr = node.attrib['id'] # "name=" attribute exists
                        #name_attr = node.attrib['name'] # "name=" attribute exists

                        try:
                            mrg_type=node.attrib['id']     
                            #mrg_type=node.attrib['mergeType']     

                            
                            try: #name='' + type='struct' + mergeType=''
                                #type_attr = node.attrib['type']
                                id_attr = node.attrib['id']
                                #if node.attrib['type']=='struct': #type='struct' + name='' + mergeType=''
                                if node.attrib['id']: #type='struct' + name='' + mergeType=''
                                    #newroot=self.vistree.AppendItem(parentnodeID, id_attr + ' = ' + node.attrib['mergeType'])
                                    newroot=self.vistree.AppendItem(parentnodeID, id_attr)
                                    self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                    #self.vistree.SetItemTextColour(newroot, 'yellow')
                                    
                                else: #type='' + name='' + mergeType=''
                                    #newroot=self.vistree.AppendItem(parentnodeID, id_attr + ' = ' + node.attrib['mergeType'] )
                                    newroot=self.vistree.AppendItem(parentnodeID, id_attr)
                                    self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum}) 
                                    #self.vistree.SetItemTextColour(newroot, 'green')
                                    
                            except KeyError: # name='' + mergeType=''
                                if node.text==None or node.text.isspace():
                                    newroot=self.vistree.AppendItem(parentnodeID, name_attr + " = " + node.attrib['mergeType'])
                                    self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                    self.vistree.SetItemTextColour(newroot, 'red')
                                else:
                                    newroot=self.vistree.AppendItem(parentnodeID, name_attr + " = " + node.attrib['mergeType']+'='+node.text)
                                    self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum}) 
                                    #self.vistree.SetItemTextColour(newroot, 'orange')  
                        except:    
                            if node.text==None or node.text.isspace():# Only name=' '
                                name_attr=node.attrib['name']
                                newroot=self.vistree.AppendItem(parentnodeID, name_attr)
                                self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                #self.vistree.SetItemTextColour(newroot, 'red')

                            else: 
                                content=node.text # name=' ' + content
                                name_attr=node.attrib['name']                                   
                                newroot=self.vistree.AppendItem(parentnodeID, name_attr + "=" + content)
                                self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                self.vistree.SetItemTextColour(newroot, 'blue')                                     


                    except KeyError:# name= ' ' DNE.    
                        
                        if node.text==None or node.text.isspace():
                            data=node.tag # 
                            #data=node.text
                            print("line 552: " + data)
                            newroot=self.vistree.AppendItem(parentnodeID, data)
                            self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})            
                            #self.vistree.SetItemTextColour(newroot, 'cyan')
                        else:
                            #data=node.tag # 
                            data=node.text
                            newroot=self.vistree.AppendItem(parentnodeID,data)
                            self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})            
                            #self.vistree.SetItemTextColour(newroot, 'cyan')
                            
                treedic[node]=newroot # append dictionary
            StGernodeID,cookie=self.vistree.GetFirstChild(rootnode) # Use StGermainData as parent node   
            VarList(self,StGernodeID)
            
            
        ## -------------- END of Standard XML parsing ---------- ##    
            

        else:    
            #process_flat(roottree)
            print ("line 571")
            initialize(self,'XML Flatfile',lnum)
            #print "This is a Flatfile!!!"
            #print ' FLAT namespace = ', namespace
        
            for node in roottree.iter():        
                
                #if node.tag in validtag:
                if node.tag in iavm_validtag:
                                    
                    # FLATFILE PROCESS
                    try:
                        parentnodeID=treedic[node.getparent()]
                           
                    except KeyError:# for StGerMainData root  Parent type None 
                        parentnodeID=treedic[parentnode_txt]

                    lnum=node.sourceline-1
                    try: 
                        name_attr = node.attrib['name'] # "name=" attribute exists
                        if node.attrib['type']=="struct" or node.attrib['type']=="list": # "type="
                            newroot=self.vistree.AppendItem(parentnodeID, name_attr)
                            self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                        
                        if node.attrib['name']=="":
                            pass # filter empty name=""    
                        
                        
                        elif node.attrib['type']=='param':
                            try:
                                content=node.text
                                newroot=self.vistree.AppendItem(parentnodeID, name_attr + " = " + content)
                                self.vistree.SetItemTextColour(newroot, 'blue')                    
                                
                            except:
                                newroot=self.vistree.AppendItem(parentnodeID, name_attr)
                            
                            try:
                                self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                
                            except IndexError:   
                                pass                             


                    except KeyError: # name= ' ' DNE. Only 'struct' attribute name may exist   
                        
                        try: 
                            type_attr = node.attrib['type']
                            if node.attrib['type']=='struct':
                                newroot=self.vistree.AppendItem(parentnodeID, type_attr)
                                self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                
                            elif node.attrib['type']=='param':
                                data=node.text
                                newroot=self.vistree.AppendItem(parentnodeID, data)
                                self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum}) 

                        except:
                            if node.text==None or node.text.isspace():
                            
                                data=node.tag # has no 'type=' in line can only be main group e.g. "components"
                                newroot=self.vistree.AppendItem(parentnodeID, data)
                                self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                #self.vistree.SetItemTextColour(newroot, 'red')  
                            else:
                                data=node.text # has no 'type=' in line can only be main group e.g. "components"
                                newroot=self.vistree.AppendItem(parentnodeID, data)                                
                                self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
                                #self.vistree.SetItemTextColour(newroot, 'green')

                treedic[node]=newroot # append dictionary

                

            VarList(self,parentnodeID)
            #self.vistree.Expand(rootnode)


        #VarList(self,parentnodeID) 
            
        self.vistree.ExpandAll() # Default expand all of tree on load
    # END ------ loadtree -----------       
                
class MyHtmlFrame(wx.Frame):
    
    
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, -1, title,  size=(800, 750))
        self.html = wx.html.HtmlWindow(self)
        wx.CallAfter(self.html.LoadPage, "http://www.auscope.monash.edu.au/codex-bleeding-edge/")
        
        # Tool Bar
        self.frame_1_toolbar = wx.ToolBar(self, -1)
        self.SetToolBar(self.frame_1_toolbar)
        self.frame_1_toolbar.AddLabelTool(1, "Search",
             wx.Bitmap(os.path.expanduser('./search_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Search", "Search CODEX")
        self.frame_1_toolbar.AddLabelTool(2, "Previous",
             wx.Bitmap(os.path.expanduser('./arrow_sans_left_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Previous", "Previous search item")
        self.frame_1_toolbar.AddLabelTool(3, "Next",
             wx.Bitmap(os.path.expanduser('./arrow_sans_right_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Next", "Next search item")
        self.frame_1_toolbar.AddSeparator()
        self.frame_1_toolbar.AddLabelTool(4, "Exit",
             wx.Bitmap(os.path.expanduser('./logout_16.png'), wx.BITMAP_TYPE_ANY),
             wx.NullBitmap, wx.ITEM_NORMAL, "Exit", "Exit CODEX Viewer")
        self.frame_1_toolbar.AddSeparator()             
        self.searchdiag= wx.SearchCtrl(self.frame_1_toolbar, 9, "", wx.DefaultPosition , wx.Size(250, 30),style=wx.TE_PROCESS_ENTER )   
        self.frame_1_toolbar.AddControl(self.searchdiag)         
        

        
        # Tool Bar end

        self.frame_1_statusbar = self.CreateStatusBar(1, 0)
        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_TOOL, self.OnSearch, id=1)
        self.Bind(wx.EVT_TOOL, self.OnPrev, id=2)
        self.Bind(wx.EVT_TOOL, self.OnNext, id=3)
        self.Bind(wx.EVT_TOOL, self.OnExit, id=4)
        self.Bind(wx.EVT_TEXT_ENTER, self.OnSearch, id = 9)         
# ------------------end wxGlade -----------------

    def __set_properties(self):
        # begin wxGlade: MyFrame.__set_properties
        self.SetTitle("CODEX Browser")
        self.SetMinSize((800, 700))
        self.frame_1_toolbar.Realize()
        self.frame_1_statusbar.SetStatusWidths([-1])
        # statusbar fields
        frame_1_statusbar_fields = ["Underworld Components"]
        for i in range(len(frame_1_statusbar_fields)):
            self.frame_1_statusbar.SetStatusText(frame_1_statusbar_fields[i], i)
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyFrame.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        #self.SetAutoLayout(True)
        sizer_1.Add(self.html,  1,  wx.EXPAND)
        self.SetSizer(sizer_1)
        self.Centre()
        self.Layout()
        # end wxGlade

    def OnExit(self, event): # wxGlade: MyFrame.<event_handler>
        self.Close()
        event.Skip()

    def OnPrev(self, event): # wxGlade: MyFrame.<event_handler>
        #self.frame_1_statusbar.SetStatusText("Event handler `OnPrevious'")
        event.Skip()

    def OnNext(self, event): # wxGlade: MyFrame.<event_handler>
        #self.frame_1_statusbar.SetStatusText("Event handler `OnNext'")
        event.Skip()

    def OnSearch(self, event): # wxGlade: MyFrame.<event_handler>
        #self.frame_1_statusbar.SetStatusText("Event handler `OnSearch'")
        event.Skip()


    
class MyApp(wx.App):
    def OnInit(self):
        global frame
        frame = MyFrame(None, -1, 'XMLViewer.py', pos=wx.DefaultPosition, size=(1250, 750),
                 style=wx.DEFAULT_FRAME_STYLE)
        tree = etree.parse(inputfile)
        namespace = tree.getroot().tag[1:].split("}")[0]
        strip_namespace(tree,namespace, True)
        frame.Show()
        frame.loadtree(tree) # Load default "empty" XML on startup
        self.SetTopWindow(frame)
        return 1

if __name__ == "__main__":
    
        try:
            main(sys.argv[1])

        except:# no command line argument
            pass
try:
    tree = etree.parse(inputfile)
    namespace = tree.getroot().tag[1:].split("}")[0]
    strip_namespace(tree,namespace, True)
    #strip_namespace_inplace(tree,namespace)   
    app = MyApp(0)
    app.MainLoop()

    
except Exception,inst:
    print "Unexpected error opening %s: %s" % (inputfile, inst) #no command-line argument
        
