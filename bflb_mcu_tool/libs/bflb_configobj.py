# -*- coding:utf-8 -*-
#  Copyright (C) 2016- BOUFFALO LAB (NANJING) CO., LTD.
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.

from configobj import *


class BFConfigParser:
    cfg_infile = None
    # cfg_obj = ConfigObj()

    def __init__(self, file=None):
        self.cfg_infile = file
        # self.cfg_obj = ConfigObj(self.cfg_infile)
        self.cfg_obj = {}

    def read(self, file=None):
        self.cfg_infile = file
        self.cfg_obj = ConfigObj(self.cfg_infile, encoding="UTF8")
        return self.cfg_obj

    def get(self, section, key):
        ret = self.cfg_obj[section][key]
        if ret == '""':
            return ""
        else:
            return ret

    def set(self, section, key, value):
        if self.cfg_obj.get(section):
            if key in self.cfg_obj[section]:
                self.cfg_obj[section][key] = str(value)

    def sections(self):
        return self.cfg_obj.keys()

    def delete_section(self, section):
        del self.cfg_obj[section]

    def update_section_name(self, oldsection, newsection):
        _sections = self.cfg_obj.keys()
        for _section in _sections:
            print(_section)
            if _section == oldsection:
                print(self.cfg_obj[_section])
                self.cfg_obj[newsection] = self.cfg_obj[oldsection]
        self.delete_section(oldsection)

    def options(self, section):
        return self.cfg_obj[section]

    def has_option(self, section, key):
        _sections = self.cfg_obj.keys()
        for _section in _sections:
            if _section == section:
                for _key in self.cfg_obj[_section]:
                    if _key == key:
                        return True
                    else:
                        continue
            else:
                continue
        return False

    def write(self, outfile=None, flag=None):
        if outfile is None:
            self.cfg_obj.filename = self.cfg_infile
        else:
            self.cfg_obj.filename = outfile
        self.cfg_obj.write()


if __name__ == "__main__":
    obj = BFConfigParser()
