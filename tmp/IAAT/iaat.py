
import	sys
import	wx
import wx.aui
import wx.grid
import wx.stc as stc
import io, re,os, wx.html
from lxml import etree

#----------------------------------------------------------------------------

pretty=False
scrolltxt=True
iavm_validtags=['IAVMtoCVE', 'IAVM', 'S', 'Revision', 'CVEs', 'CVENumber', 'Vendor','CPEs','CPE','References', 'Reference',]
swcat_validtags=['ai:assets','assets','ai','Asset','ai:CanonicalID','CanonicalID','Software','ai:CPE','CPE',]

#----------------------------------------------------------------------------

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

#----------------------------------------------------------------------------

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

#----------------------------------------------------------------------------

class TestNB(wx.Notebook):
	def __init__(self, parent, id, log):
		wx.Notebook.__init__(self, parent, id, size=(21,21), style=wx.BK_DEFAULT)
		self.log = log

		self.home= HomePanel(self)
		self.AddPage(self.home, "Home")

		self.iavm= MyXmlPanel(self,"", iavm_validtags)
		self.AddPage(self.iavm, "IAVM")

		self.swcat= MyXmlPanel(self,"", swcat_validtags)
		self.AddPage(self.swcat, "SWCAT")

		self.dash = dashGrid(self)
		self.AddPage(self.dash, "DASH")

		self.poam = poamGrid(self)
		self.AddPage(self.poam, "POAM")

		self.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.OnPageChanged)
		self.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGING, self.OnPageChanging)

	def OnPageChanged(self, event):
		old = event.GetOldSelection()
		new = event.GetSelection()
		sel = self.GetSelection()
		self.log.write('OnPageChanged,	old:%d, new:%d, sel:%d\n' % (old, new, sel))
		event.Skip()

	def OnPageChanging(self, event):
		old = event.GetOldSelection()
		new = event.GetSelection()
		sel = self.GetSelection()
		self.log.write('OnPageChanging, old:%d, new:%d, sel:%d\n' % (old, new, sel))
		event.Skip()

	def openfilemenu(self, event, mode): # wxGlade: MyFrame.<event_handler>
		""" Open a file"""
		dlg = wx.FileDialog(self, "Choose an XML file", "", "", "*.xml", wx.OPEN)
		if dlg.ShowModal() == wx.ID_OK:
			filename = dlg.GetFilename()
			dirname = dlg.GetDirectory()
			print os.path.join(dirname, filename)
		dlg.Destroy()
		if mode=="iavm":
			self.iavm.loadfile(os.path.join(dirname, filename))
			self.iavm.set_properties(os.path.join(dirname, filename))
		elif mode=="swcat":
			self.swcat.loadfile(os.path.join(dirname, filename))
			self.swcat.set_properties(os.path.join(dirname, filename))
	
	def update_dashboard(self, event): # wxGlade: MyFrame.<event_handler>
		# need iavm_tree and swcat_tree
		# for each cpe in each iavm in iavm_tree
		#     is there a match with any cpe in each asset in swcat_tree
		#         if yes, then place a mark in the iavm/asset cell
		iavm_tree = self.iavm.tree
		swcat_tree = self.swcat.tree
		print iavm_tree.getroot().tag
		print swcat_tree.getroot().tag
		iavm_root=iavm_tree.getroot()
		swcat_root=swcat_tree.getroot()
		
		iavms=iavm_root.findall('IAVM')
		assets=swcat_root.findall('ai')
		
		iavass=[] # holds row, col pairs of matches
		for i in range(len(iavms)):
			iavcpes=iavms[i].findall(".//CPE")
			iavcpetxt=[]
			for iav in iavcpes:
				iavcpetxt.append(iav.text)
			for j in range(len(assets)):
				asscpes=assets[j].findall('./Software/CPE')
				asscpetxt=[]
				for ass in asscpes:
					asscpetxt.append(ass.text)
				for c in iavcpetxt:
					if c in asscpetxt:
						iavass.append([i,j])

		self.dash.updateGrid(iavass)

#----------------------------------------------------------------------------

def runTest(frame, nb, log):
	testWin = TestNB(nb, -1, log)
	return testWin

#----------------------------------------------------------------------------

class HomePanel(wx.Panel):
	def __init__(self,parent):
		wx.Panel.__init__(self,parent)
		self.SetBackgroundColour(wx.Colour(216, 216, 191))
		self.parent = parent

		btn_iavm = wx.Button(self, 10, "Import IAVM-to-CPE", (20, 30))
		self.Bind(wx.EVT_BUTTON, lambda event: parent.openfilemenu(event, 'iavm'),btn_iavm )

		btn_swcat = wx.Button(self, 20, "Import Software Catalog", (20, 70))
		self.Bind(wx.EVT_BUTTON, lambda event: parent.openfilemenu(event, 'swcat'),btn_swcat )

		btn_dash_update = wx.Button(self, 30, "Update Dashboard", (20, 110))
		self.Bind(wx.EVT_BUTTON, lambda event: parent.update_dashboard(event),btn_dash_update )

		btn_dash_export = wx.Button(self, 40, "Export Dashboard", (20, 150))
		self.Bind(wx.EVT_BUTTON, lambda event: parent.openfilemenu(event),btn_dash_export )

class MyXmlPanel(wx.Panel):
	def __init__(self,parent,xmlfile,vtags):
		wx.Panel.__init__(self,parent)
		
		self.parent = parent

		self.validtags = vtags
		splitter = wx.SplitterWindow(self)
		leftP = wx.Panel(splitter,-1)
		rightP = wx.Panel(splitter,-1)
		
		self.stc = wx.stc.StyledTextCtrl(rightP, size=(500,700))
		self.vistree = wx.TreeCtrl(leftP, -1, size=(400, 700), style=wx.TR_HAS_BUTTONS|wx.TR_LINES_AT_ROOT|wx.TR_FULL_ROW_HIGHLIGHT|wx.TR_DEFAULT_STYLE|wx.SUNKEN_BORDER)
		self.stc.SetMarginType(1, stc.STC_MARGIN_NUMBER)
		self.stc.SetMarginWidth(1,30)
		
		splitter.SplitVertically(leftP, rightP)
		splitter.SetMinimumPaneSize(200)
 
		sizer = wx.BoxSizer(wx.VERTICAL)
		sizer.Add(splitter, 1, wx.EXPAND)
		self.SetSizer(sizer)		
		
		#self.loadfile(xmlfile)
		self.set_properties(xmlfile) 
		
	
	def set_properties(self, xmlfile):
		self.dirname=''
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
		#xml_file = inputfile
		try:
			print (xmlfile)
			self.stc.SetText(open(xmlfile).read())
		except:
			pass
		self.stc.EnsureCaretVisible()
		self.stc.SetCaretLineVisible(1)
		self.stc.SetCaretLineBack("yellow")
		self.stc.SetCaretForeground("black")
		self.stc.SetCaretWidth(2)  
			  
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
	
	def OnTextCancel(self,	event):
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
	
	def onexp(self,	 event):	
			node=self.vistree.GetSelection()
			self.vistree.Expand(node)		 
			
	def updateDashboard(self,newtree):
		print "updateDashboard: entry"
		if 'Asset' in self.validtags:
			print "updateDashboard: asset"
			ass = newtree.findall('//ai')
			assets=[]
			for a in ass:
				assets.append(a.get('id'))
			self.parent.dash.updateAssetLabels(assets)
		elif 'IAVM' in self.validtags:
			print "updateDashboard: iavm"
			iavs = newtree.findall('//S')
			iavms=[]
			for i in iavs:
				iavms.append(i.get('IAVM'))
			self.parent.dash.updateIavmLabels(iavms)
		
	def loadfile(self,xmlfilename):
		print("parse: "+xmlfilename)
		#tree = etree.parse(open(xmlfilename,'r'))
		#namespace = tree.getroot().tag[1:].split("}")[0]
		#strip_namespace(tree,namespace, True)
		self.tree = etree.parse(open(xmlfilename,'r'))
		namespace = self.tree.getroot().tag[1:].split("}")[0]
		strip_namespace(self.tree,namespace,True)	  
		#newroot=newtree.getroot()
		self.vistree.DeleteAllItems()	   
		self.loadtree(self.tree)
		#self.expandbutton.SetValue(False) 
		#self.SetStatusText(os.path.join(self.dirname, self.filename))
		self.updateDashboard(self.tree)

	def loadtree(self,roottree):
		#Populate tree structure with XML children
		rootn=roottree.getroot()
		lnum=roottree.getroot().sourceline
		newroot=rootn
		print "rootn.tag: "+rootn.tag
		
		#def initialize(self,filetype,line_num):
		filetype="XML Splat File"
		#filetype=str(rootn.tag)
		rootnode=self.vistree.AddRoot(filetype) # string parameter & returns an ID
		self.vistree.SetPyData(rootnode,{"id_num":rootnode,"line_num":lnum} ) 
		treedic={filetype:rootnode}
		parentnode_txt=filetype
		
		#initialize(self,'XML Flatfile',lnum)
		offset=lnum-1 # offset beggining of file
		print "rootn.tag 2: "+rootn.tag
		print "node.tag 2.0: "+parentnode_txt
		print "node.tag 2.1: "+str(rootnode)
		print "node.tag 2.2: "+str(treedic[parentnode_txt])
		print(self.validtags)
		
		#for node in roottree.iter():		
		for node in roottree.iter():		
			#print "node.tag 1: "+node.tag			
			if node.tag in self.validtags:
								
				# STANDARD FILE PROCESS
				#print "node.tag 2a: "+node.tag
				try:
					#print "node.tag 2a1: "+node.tag
					parentnodeID=treedic[node.getparent()]
				except KeyError:# for StGerMainData root  Parent type = None 
					#print "node.tag 2a2: "+node.tag
					#parentnodeID=treedic[parentnode_txt]
					try:
						parentnodeID=treedic[parentnode_txt]
					except:
						print("flailing")
				
				#print "lnum: "+lnum
				lnum=node.sourceline-offset
				#print "lnum: "+lnum
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


				except KeyError:# name= ' ' IAVM.	
					# setting IAVM numbers means resetting parent label
					try:
						iavm_name = node.attrib['IAVM']
						self.vistree.SetItemText(parentnodeID, iavm_name)
						newroot=self.vistree.AppendItem(parentnodeID, node.tag)
						self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})
					except:
						if node.text==None or node.text.isspace():
							data=node.tag # 
							#data=node.text
							#print("line 552: " + data)
							newroot=self.vistree.AppendItem(parentnodeID, data)
							self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})			
							#self.vistree.SetItemTextColour(newroot, 'cyan')
						else:
							#data=node.tag # 
							data=node.text
							newroot=self.vistree.AppendItem(parentnodeID,data)
							self.vistree.SetPyData(newroot, {"id_num":node,"line_num":lnum})			
							#self.vistree.SetItemTextColour(newroot, 'cyan')
			else:
				pass
				#print "node.tag 2b: "+node.tag
			#print "rootn.tag 3: "+rootn.tag
			treedic[node]=newroot # append dictionary
		#StGernodeID,cookie=self.vistree.GetFirstChild(rootn) # Use StGermainData as parent node	 
		
	#self.vistree.ExpandAll() # Default expand all of tree on load
# END ------ loadtree -----------		

class dashGrid(wx.grid.Grid):
	def __init__(self, parent):
		wx.grid.Grid.__init__(self,parent,size = (1500,1000))
		self.parent = parent
		self.SetDefaultCellOverflow(False)
		self.EnableEditing(False)
		#self.EnableDragGridSize(False)
		#self.EnableDragRowSize(False)
		#self.EnableDragColSize(False)
		#self.grid = wx.grid.Grid(parent)
		self.SetColLabelSize(100)
		self.CreateGrid(3000,20)
		self.SetColLabelAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
		self.SetColLabelTextOrientation(wx.VERTICAL)
		self.AutoSizeColumns(setAsMin=True)
	
	def updateIavmLabels(self,iavms):
		print('updateIavmLabels')
		for i in range(self.GetNumberRows()):
			self.SetRowLabelValue(i,"")
		for i in range(len(iavms)):
			self.SetRowLabelValue(i, iavms[i])
	
	def updateAssetLabels(self,assets):
		print('updateAssetLabels')
		for i in range(self.GetNumberCols()):
			self.SetColLabelValue(i,"")
		for i in range(len(assets)):
			self.SetColLabelValue(i, assets[i])

	def updateGrid(self,mycells):
		self.ClearGrid()
		for mc in mycells:
			self.SetCellValue(mc[0], mc[1], "X")

class poamGrid(wx.grid.Grid):
	def __init__(self, parent):
		wx.grid.Grid.__init__(self,parent,size = (1500,1000))
		self.SetDefaultCellOverflow(False)
		self.EnableEditing(False)
		self.EnableDragGridSize(False)
		self.EnableDragRowSize(False)
		self.EnableDragColSize(False)
		#self.grid = wx.grid.Grid(parent)
		self.CreateGrid(20, 12)
		self.SetColLabelValue(0, "ID")
		self.SetColSize(0, 200)
		self.SetColLabelValue(1, "Weakness")
		self.SetColLabelValue(2, "POC")
		self.SetColLabelValue(3, "Resources Required")
		self.SetColLabelValue(4, "Scheduled Completion Date")
		self.SetColSize(4, 110)
		self.SetColLabelValue(5, "Milestones with Completion Date")
		self.SetColSize(5, 110)
		self.SetColLabelValue(6, "Changes to Milestones")
		self.SetColLabelValue(7, "Identified by?")
		self.SetColLabelValue(8, "Completion Date")
		self.SetColSize(8, 125)
		self.SetColLabelValue(9, "Status")
		self.SetColSize(9, 165)
		self.SetColLabelValue(10, "Comments")
		self.SetColSize(10, 200)
		self.SetColLabelValue(11, "Risk Level")
		self.SetColSize(11, 200)
		self.SetColLabelValue(12, "Weakness Severity")
		#self.AutoSizeColumns(setAsMin=True)


overview = """\
<html><body>
<h2>wx.Notebook</h2>
<p>
This class represents a notebook control, which manages multiple
windows with associated tabs.
<p>
To use the class, create a wx.Notebook object and call AddPage or
InsertPage, passing a window to be used as the page. Do not explicitly
delete the window for a page that is currently managed by wx.Notebook.

"""


if __name__ == '__main__':
	import sys,os
	import run
	run.main(['', os.path.basename(sys.argv[0])] + sys.argv[1:])

