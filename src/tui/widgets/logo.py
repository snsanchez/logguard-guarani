from textual.widgets import Static

RESTING = r"""
     __
 __(o )>
 \ <_. )
  `---'
"""


WORKING = r"""
     __
 __(O )>
 \ <_\ )
  `---'
"""


SUCCESS = r"""
     __
 __(^ )>
 \ <_. )
  `---'
"""


ERROR = r"""
     __
 __(x )>
 \ <_. )
  `---'
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
