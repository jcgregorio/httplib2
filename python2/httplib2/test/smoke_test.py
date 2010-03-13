import os
import logging
import unittest

import httplib2

from httplib2.test import miniserver
import SimpleHTTPServer

HERE = os.path.dirname(__file__)
logger = logging.getLogger(__name__)


class ThisDirHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = path.split('?', 1)[0].split('#', 1)[0]
        return os.path.join(HERE, *filter(None, path.split('/')))

    def log_message(self, s, *args):
        # output via logging so nose can catch it
        logger.info(s, *args)


class HttpSmokeTest(unittest.TestCase):
    def setUp(self):
        self.httpd, self.port = miniserver.start_server(ThisDirHandler)

    def tearDown(self):
        self.httpd.shutdown()

    def testGetFile(self):
        client = httplib2.Http()
        src = os.path.basename(__file__)
        response, body = client.request('http://localhost:%d/%s' %
                                        (self.port, src))
        self.assertEqual(response.status, 200)
        self.assertEqual(body, open(os.path.join(HERE, src)).read())
