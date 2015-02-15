
import	sys
import	wx
import wx.aui
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
		wx.Notebook.__init__(self, parent, id, size=(21,21), style=
							 wx.BK_DEFAULT
							 #wx.BK_TOP 
							 #wx.BK_BOTTOM
							 #wx.BK_LEFT
							 #wx.BK_RIGHT
							 # | wx.NB_MULTILINE
							 )
		self.log = log

		win = self.makeColorPanel(wx.BLUE)
		self.AddPage(win, "Home")
		st = wx.StaticText(win.win, -1,
						  "You can put nearly any type of window here,\n"
						  "and if the platform supports it then the\n"
						  "tabs can be on any side of the notebook.",
						  (10, 10))

		st.SetForegroundColour(wx.WHITE)
		st.SetBackgroundColour(wx.BLUE)
		
		page1= MyXmlPanel(self,"u_iavm-to-cve.xml", iavm_validtags)
		self.AddPage(page1, "IAVM")

		page1= MyXmlPanel(self,"ai-swcat-generic.xml", swcat_validtags)
		self.AddPage(page1, "SWCAT")

		win = self.makeColorPanel(wx.CYAN)
		self.AddPage(win, "POAM")

		self.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.OnPageChanged)
		self.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGING, self.OnPageChanging)


	def makeColorPanel(self, color):
		p = wx.Panel(self, -1)
		win = wx.Panel(p, -1)
		p.win = win
		def OnCPSize(evt, win=win):
			win.SetPosition((0,0))
			win.SetSize(evt.GetSize())
		p.Bind(wx.EVT_SIZE, OnCPSize)
		return p


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


#----------------------------------------------------------------------------

def runTest(frame, nb, log):
	testWin = TestNB(nb, -1, log)
	return testWin

#----------------------------------------------------------------------------
class NoteBookPage(wx.Panel):
	def __init__(self,parent,message):
		wx.Panel.__init__(self,parent)
		sizer= wx.BoxSizer(wx.VERTICAL)
		message= wx.StaticText(self,label=message)
		sizer.Add(message,1,wx.ALIGN_CENTRE)
		self.SetSizer(sizer)

class MyXmlPanel(wx.Panel):
	def __init__(self,parent,xmlfile,validtags):
		wx.Panel.__init__(self,parent)
		
		#self.mgr = wx.aui.AuiManager(self)

		#leftpanel = wx.Panel(self, -1)
		#rightpanel = wx.Panel(self, -1)
		#bottompanel = wx.Panel(self, -1)
		
		splitter = wx.SplitterWindow(self)
		leftP = wx.Panel(splitter,-1)
		rightP = wx.Panel(splitter,-1)
		
		self.stc = wx.stc.StyledTextCtrl(rightP, size=(500,700))
		self.vistree = wx.TreeCtrl(leftP, -1, size=(400, 700), style=wx.TR_HAS_BUTTONS|wx.TR_LINES_AT_ROOT|wx.TR_FULL_ROW_HIGHLIGHT|wx.TR_DEFAULT_STYLE|wx.SUNKEN_BORDER)
		self.stc.SetMarginType(1, stc.STC_MARGIN_NUMBER)
		self.stc.SetMarginWidth(1,30)
		
		#self.mgr.AddPane(bottompanel, wx.aui.AuiPaneInfo().Bottom(), 'Information Pane')
		#self.mgr.AddPane(self.vistree, wx.aui.AuiPaneInfo().Left().Layer(0),'Tree Navigator')
		#self.mgr.AddPane(self.stc, wx.aui.AuiPaneInfo().Center().Layer(1), 'Editor Pane')		 
		
		#self.mgr.Update()
		splitter.SplitVertically(leftP, rightP)
		splitter.SetMinimumPaneSize(200)
 
		sizer = wx.BoxSizer(wx.VERTICAL)
		sizer.Add(splitter, 1, wx.EXPAND)
		self.SetSizer(sizer)		
		
		self.__set_properties(xmlfile) 
		
		try:
			print("parse: "+xmlfile)
			tree = etree.parse(xmlfile)
			namespace = tree.getroot().tag[1:].split("}")[0]
			strip_namespace(tree,namespace, True)
			self.loadtree(tree,validtags)
		except:
			print("failed to init tree")
			pass
	
	def __set_properties(self, xmlfile):
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
	
	def loadtree(self,roottree,validtags):
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
		print(validtags)
		
		#for node in roottree.iter():		
		for node in roottree.iter():		
			#print "node.tag 1: "+node.tag			
			if node.tag in validtags:
								
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
		StGernodeID,cookie=self.vistree.GetFirstChild(rootn) # Use StGermainData as parent node	 
		
	#self.vistree.ExpandAll() # Default expand all of tree on load
# END ------ loadtree -----------		


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

