from textual.widgets import Static

# jp2a "archivo" --size=32x14
RESTING = r"""
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMWNKKKKNMMMMMMMMMMMMMMMMM
MMMMWkl,........;o0MMMMMMMMMMMMM
MMKc....':cc:,,'...,xWMMMMMMMMMM
Wl..,o0WMMMOoxkcc:,'.,codkOKXWMM
'.oXWWMWKON   K'''','........'oK
xNNXkl,...:dldc..'.    .,cx0NMMM
0o,...........':::;'.oXMMMMMMMMM
.. .........'cccc:::0MMMMMMMMMMM
.. .........llll:::xMMMMMMMMMMMM
...  ......,llllcccKMMMMMMMMMMMM
,,'.........:oollll0MMMMMMMMMMMM
cllooc;'.....,colll:0MMMMMMMMMMM
ccclloooc......:oo:..0MMMMMMMMMM
"""


class LogoWidget(Static):
    def resting(self):

        self.update(RESTING)

    def working(self):

        self.update(WORKING)

    def success(self):

        self.update(SUCCESS)

    def error(self):

        self.update(ERROR)
