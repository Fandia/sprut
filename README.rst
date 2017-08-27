**sprut**
=========

**sprut** is a simple python-module for brute-force attacks, that can be used in your scripts.

**sprut** supports ssh, http-post services. Other popular services and command-line interface will soon be implemented.

Features
^^^^^^^^
* Multithreading
* Load balancing
* Modular design

Requirements
^^^^^^^^^^^^
* Python3
* paramiko, requests packages

Quick start
^^^^^^^^^^^
1. Create ``BruteForce`` object:

	>>> b = sprut.BruteForce()
2. Initialization tasks for attack:

	>>> b.init_tasks(...)

3. Run attack!

	>>> b.run(...)

*Usage examples:*

SSH login-password attack:

	>>> b = sprut.BruteForce()
	>>> b.init_tasks(target = ['localhost'],
	... login = ['admin','user'],
	... password = sprut.get_lines_from_file('/home/file_with_passes'))
	>>> success = b.run(sprut.Ssh, out_file='/home/success')

HTTP-POST attack with proxy:

	>>> b = sprut.BruteForce()
	>>> b.set_proxy('http','127.0.0.1', 8080)
	>>> b.init_tasks(target=['http://example.com/login'],
	... login=sprut.get_lines_from_file('/home/file_with_logins'),
	... password=['pass','1234'],
	... some_key=['111111','222222'],
	... body=['user=^login^&pass=^password^&user_key=^some_key^'],
	... fail_msg=['fail'])
	>>> success = b.run(sprut.HttpPost, out_file='/home/success')