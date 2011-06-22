"""
httplib2test_appengine

A set of unit tests for httplib2.py on Google App Engine

"""

__author__ = "Joe Gregorio (joe@bitworking.org)"
__copyright__ = "Copyright 2011, Joe Gregorio"

import os
import sys
import unittest

# The test resources base uri
base = 'http://bitworking.org/projects/httplib2/test/'
#base = 'http://localhost/projects/httplib2/test/'
cacheDirName = ".cache"
APP_ENGINE_PATH='../../google_appengine'

sys.path.insert(0, APP_ENGINE_PATH)

import dev_appserver
dev_appserver.fix_sys_path()

from google.appengine.ext import testbed
testbed = testbed.Testbed()
testbed.activate()
testbed.init_urlfetch_stub()

import httplib2

class AppEngineHttpTest(unittest.TestCase):
    def setUp(self):
        if os.path.exists(cacheDirName): 
            [os.remove(os.path.join(cacheDirName, file)) for file in os.listdir(cacheDirName)]

        if sys.version_info < (2, 6):
            disable_cert_validation = True
        else:
            disable_cert_validation = False

    def test(self):
        h = httplib2.Http()
        response, content = h.request("http://bitworking.org")
        self.assertEqual(httplib2.SCHEME_TO_CONNECTION['https'],
                         httplib2.AppEngineHttpsConnection)
        print h.connections
        self.assertEquals(1, len(h.connections))
        self.assertEquals(type(h.connections['http:bitworking.org']),
                          httplib2.AppEngineHttpConnection)
        self.assertEquals(response.status, 200)
        self.assertEquals(response['status'], '200')

    def test_no_key_or_cert_file(self):
        h = httplib2.Http(proxy_info='foo.txt')
        try:
          response, content = h.request("http://bitworking.org")
          self.fail('Should raise exception.')
        except httplib2.NotSupportedOnThisPlatform:
          pass

if __name__ == '__main__':
    unittest.main()
