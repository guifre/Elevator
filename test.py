import unittest

import mock as mock

from escalator import find_keywords, run


class EscalatorTest(unittest.TestCase):
    def test_whenUnameHas64BitsAndKernelVersion_thenExpectedResultFound(self):
        self.assertEqual(
            find_keywords('Linux kali 4.11.0-kali1-amd64 #1 SMP Debian 4.11.6-1kali1 (2017-06-21) x86_64 GNU/Linux'),
            ({'os': 'linux', 'version': '4.11'})
        )

    def test_whenExploitRun_thenExpectedSystemCallsMade(self):
        url_opener = mock.Mock()
        mock.return_value = ['foo']
        with mock.patch('os.popen3', create=True) as mock_os_open3:
            mock_os_open3.return_value = (mock.MagicMock(spec=file), mock.MagicMock(spec=file), mock.MagicMock(spec=file))
            run({'file': 'alpha/bravo.c', 'description' : 'charlie'}, url_opener)
            assert url_opener.mock_calls == [
                mock.call.retrieve('https://raw.githubusercontent.com/offensive-security/exploit-database/master/alpha/bravo.c', 'bravo.c')
            ]
            assert mock_os_open3.mock_calls == [
                mock.call('gcc bravo.c -o bravo -lpthread -pthread -lcrypt -lssl -ldl', 'r'),
                mock.call('rm bravo.c', 'r'),
                mock.call('rm bravo', 'r')
            ]