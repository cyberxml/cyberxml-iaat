Underworld Flatfile Viewer 
Septemeber 2011


Search and Tree type navigation through flatened and standard Underworld XML input files. No editing functions availale as yet.

Icons must be located in subdir: eg. home/<USERNAME>/bleedingEdge/Underworld/UWViewer/icons
where the Directory "UWViewer" contains the Underworld viewer.

NB: Viewer.py requires wx.Python 2.8 & Python 2.6 or above for Ubuntu. Also lxml parsing library is required

------------ wxPython ------------

Goto:
http://www.wxpython.org/

Stable releases are here;

http://www.wxpython.org/download.php#stable

MAC OSX Binaries;
(Match the version to Python version.)

http://downloads.sourceforge.net/wxpython/wxPython2.8-osx-unicode-2.8.12.1-universal-py2.6.dmg

http://downloads.sourceforge.net/wxpython/wxPython2.8-osx-unicode-2.8.12.1-universal-py2.7.dmg

UBUNTU & DEBIAN releases install instructions;

http://wiki.wxpython.org/InstallingOnUbuntuOrDebian

------------ lxml 2.3 ---------


## Win & Linux

For download and installation of lxml, go here;  http://lxml.de/index.html#download

Installation instructions are here;   http://lxml.de/installation.html

Download lxml 2.3:
http://pypi.python.org/pypi/lxml/2.3



## MACOSX

NOTE: If you have lxml installed already, you may need to type in the following command;

"defaults write com.apple.versioner.python Prefer-32-Bit -bool yes"

Otherwise you can install lxml using "easy_install" here ; http://peak.telecommunity.com/DevCenter/EasyInstall

If you have downloaded the egg file locally, then use the following command;

"sudo easy_install /my_downloads/OtherPackage-3.2.1-py2.3.egg"

Download the egg here; http://pypi.python.org/pypi/lxml/2.3

e.g. Choose
lxml-2.3-py2.7-macosx-10.6-intel.egg (md5)
(32bit/64bit built on Mac Intel (Core2Duo) 10.6.6, using libxml2 2.7.8, libxslt 1.1.26, libiconv 1.13.1, zlib-1.2.5)



Major Changes:

1: Use of wx.aui frame and panels for better GUI interface
	Panels can detach, re-attach, moved and be removed (Future expansion is made much simpler)
	
2: Viewer can now read standard XML input files

  


