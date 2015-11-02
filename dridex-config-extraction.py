#!/usr/bin/python

## Dridex configuration extractor - v 1.0
## Copyright (c) 2015 Nagravision SA
## Written by Marc Doudiet & Raphael Frei
## Thanks to @Xylit0l for the hints and sample
## Tested on sampple md5: ed9847f3147f21d9825d09d432ecea3c (dridex301) & f2b660069dfdf8d79139ea083d45ece2 (dridex 120)
## Tested with version pefile-1.2.10
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import pefile
import itertools
import argparse
from binascii import *
imported_aplib = __import__('aplib')

parser = argparse.ArgumentParser(description='Dridex config extractor')
parser.add_argument('-f', dest='filename', help='Filename of the dridex sample',required=True)
args = parser.parse_args()

pe = pefile.PE(args.filename)
numsec = 0
print '##########################################'
print 'Dridex configuration extractor'
print '##########################################\n'

#pe = pefile.PE('ED9847F3147F21D9825D09D432ECEA3C')
for section in pe.sections:
	#numsec += 1
	print 'Section found: ',section.Name
	xorkey = section.get_data()[:4]
	print 'Trying to de-xor with key: ',hexlify(xorkey)
	data = section.get_data()[12:]
	decrypted =  ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(data, itertools.cycle(xorkey)))
	print 'Decrypted raw: ',decrypted[:30],'hex: ',hexlify(decrypted[:30])
	if '<conf' in decrypted:
		print '\n--> Found "conf" in section, trying to decompress (aplib) ...'
		try:
			config_raw = imported_aplib.decompress(decrypted).do()
			print '\n--> ### Success !!! Found correct section: ',section.Name
			print '--> ### RAW configuration: ',config_raw,'\n'
			config = config_raw[0]
			config_start = config.find('<config')
			print '##########################################\n'
			print config[config_start:],'\n'
		except:
			print 'Not able to decompress with aplib ...'
	else:
		print 'Conf not found in decrypted ... continuing ...'
