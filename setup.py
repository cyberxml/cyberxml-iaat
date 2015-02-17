from distutils.core import setup
import py2exe
import glob

setup(
	console=['iaat.py'],
	data_files=[
		("docs",glob.glob("docs/*.xml")),
	],
)

'''
setup(
   windows = [
        {
            "script": "src/iaat.py",
            "icon_resources": [(1, "src/icons/logout_16.png")]
        }
    ],
)
'''