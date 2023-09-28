#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright 2023 Huawei Cloud Computing Technology Co., Ltd.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""

from distutils.core import setup, Extension

uoa = Extension('uoa', sources=['uoamodule.c'], include_dirs=['../../../include/'])

setup(name='UOA C Extension Module',
      version='1.0',
      description='This is a module used to invoke the interface of the UOA kernel module',
      ext_modules=[uoa])
